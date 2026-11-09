package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/confirm"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/hub"
)

// Plan 4 Task 14: confirmations (contract §15.6, §15.7, §5.1; G11, G12,
// G26, G27, G75).

// confirmFA is a fresh-auth verifier whose answer the test sets.
type confirmFA struct {
	mu       sync.Mutex
	base     string
	authTime time.Time // zero: now − 10 s
	amr      []string  // nil: hwk
	err      error
	calls    int
}

func (f *confirmFA) Info() freshauth.AuthorizeInfo {
	return freshauth.AuthorizeInfo{AuthorizeURL: "https://auth.example.org/realms/portcullis/protocol/openid-connect/auth", ClientID: freshauth.ClientID, RedirectURI: f.base}
}

func (f *confirmFA) Verify(_ context.Context, p freshauth.Proof, user string) (*freshauth.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	if p.Code != "good-code" {
		return nil, &freshauth.Error{Reason: "code exchange failed"}
	}
	at, amr := f.authTime, f.amr
	if at.IsZero() {
		at = time.Now().Add(-10 * time.Second)
	}
	if amr == nil {
		amr = []string{"hwk"}
	}
	return &freshauth.Result{User: user, AuthTime: at, AMR: amr}, nil
}

func (f *confirmFA) set(at time.Time, amr []string, err error) {
	f.mu.Lock()
	f.authTime, f.amr, f.err = at, amr, err
	f.mu.Unlock()
}

func (f *confirmFA) n() int { f.mu.Lock(); defer f.mu.Unlock(); return f.calls }

type confirmEnv struct {
	*mcpEnv
	people, hubFA *confirmFA
}

func newConfirmEnv(t *testing.T) *confirmEnv {
	t.Helper()
	return newConfirmEnvOpts(t, mcpEnvOpts{})
}

// newConfirmEnvOpts is newConfirmEnv over newMCPEnvOpts.
func newConfirmEnvOpts(t *testing.T, o mcpEnvOpts) *confirmEnv {
	t.Helper()
	e := newMCPEnvOpts(t, o)
	pfa := &confirmFA{base: "https://people.example.org/"}
	hfa := &confirmFA{base: "https://hub.example.org/"}
	e.s.Hub.SetFreshAuth(hub.ListenerPeople, pfa)
	e.s.Hub.SetFreshAuth(hub.ListenerHub, hfa)
	e.s.Hub.SetFreshAuthReadyForTest(true)
	return &confirmEnv{mcpEnv: e, people: pfa, hubFA: hfa}
}

func sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// createBody is a POST /internal/confirmations body for canonical args.
func createBody(user, tool, args, reason string) string {
	b, _ := json.Marshal(map[string]string{"user": user, "client": "portcullis-ai-claude", "resource": aiappResource, "tool": tool,
		"args_sha256": sha(args), "args_preview": args, "reason": reason})
	return string(b)
}

func consumeBody(user, tool, args string) string {
	b, _ := json.Marshal(map[string]string{"user": user, "resource": aiappResource, "tool": tool, "args_sha256": sha(args)})
	return string(b)
}

// wantConfirmCSP is the page's Content-Security-Policy (fix round 1).
const wantConfirmCSP = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// framingHeaders: the page can't be framed and runs only its own scripts.
func framingHeaders(t *testing.T, where string, h interface{ Get(string) string }) {
	t.Helper()
	if h.Get("X-Frame-Options") != "DENY" || h.Get("Content-Security-Policy") != wantConfirmCSP {
		t.Errorf("%s: X-Frame-Options %q, CSP %q", where, h.Get("X-Frame-Options"), h.Get("Content-Security-Policy"))
	}
}

var confirmIDR = regexp.MustCompile(`^[A-Z2-7]{4}(-[A-Z2-7]{4}){5}-[A-Z2-7]{2}$`)

// create makes a companion confirmation through the internal API → its id.
func (e *confirmEnv) create(t *testing.T, user, tool, args string) string {
	t.Helper()
	code, b := e.post(t, "/internal/confirmations", createBody(user, tool, args, "confirm"))
	if code != 201 {
		t.Fatalf("create %s %s = %d %s", user, tool, code, b)
	}
	var a map[string]string
	json.Unmarshal([]byte(b), &a)
	return a["id"]
}

func decision(decision, typed, code string) string {
	b, _ := json.Marshal(map[string]string{"decision": decision, "typed": typed, "code": code,
		"code_verifier": strings.Repeat("v", 43), "nonce": "n0nce"})
	return string(b)
}

func (e *confirmEnv) confirmAudit(t *testing.T) []directory.AuditEntry {
	return e.auditOf(t, "ai.confirm")
}

// TestInternalConfirmations (§15.7, G26, G27): create → 201 {id, url,
// expires_at} with url https://people.example.org/confirm/<id>; consume
// before approval → 409 pending; after → 200 {id}; again → 404; a
// decline → 409 declined; only current companion resources and their
// population; reason confirm needs the companion's confirm patterns;
// the preview must be the digest's bytes; over the limit → 429
// too_many, audited refused; Portcullis-resource confirmations are never
// consumed here.
func TestInternalConfirmations(t *testing.T) {
	e := newConfirmEnv(t)
	args := `{"name":"repo-1"}`
	code, b := e.post(t, "/internal/confirmations", createBody("alice", "delete_repo", args, "confirm"))
	if code != 201 {
		t.Fatalf("create = %d %s", code, b)
	}
	var a struct {
		ID        string `json:"id"`
		URL       string `json:"url"`
		ExpiresAt string `json:"expires_at"`
	}
	dec := json.NewDecoder(strings.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil || !confirmIDR.MatchString(a.ID) || a.URL != "https://people.example.org/confirm/"+a.ID {
		t.Fatalf("create answer %s (%v)", b, err)
	}
	if exp, err := time.Parse(time.RFC3339, a.ExpiresAt); err != nil || time.Until(exp) < 9*time.Minute || time.Until(exp) > 10*time.Minute+time.Second {
		t.Errorf("expires_at %q", a.ExpiresAt)
	}
	// The same binding while pending: the same confirmation.
	if _, b2 := e.post(t, "/internal/confirmations", createBody("alice", "delete_repo", args, "confirm")); !strings.Contains(b2, a.ID) {
		t.Errorf("re-create = %s", b2)
	}
	if code, b := e.post(t, "/internal/confirmations/consume", consumeBody("alice", "delete_repo", args)); code != 409 || b != `{"state":"pending"}` {
		t.Errorf("consume pending = %d %s", code, b)
	}
	if r, b := doAs(t, e.ppl, "alice", "POST", "/api/me/confirmations/"+a.ID, decision("approve", "AI App", "good-code")); r.StatusCode != 200 || strings.TrimSpace(b) != `{"state":"approved"}` {
		t.Fatalf("approve = %d %s", r.StatusCode, b)
	}
	// Another person, tool or argument never consumes it.
	for _, c := range [][2]string{{"bob", "delete_repo"}, {"alice", "delete_other"}} {
		if code, b := e.post(t, "/internal/confirmations/consume", consumeBody(c[0], c[1], args)); code != 404 {
			t.Errorf("consume %v = %d %s", c, code, b)
		}
	}
	if code, _ := e.post(t, "/internal/confirmations/consume", consumeBody("alice", "delete_repo", `{"name":"repo-2"}`)); code != 404 {
		t.Errorf("other args consumed = %d", code)
	}
	if code, b := e.post(t, "/internal/confirmations/consume", consumeBody("alice", "delete_repo", args)); code != 200 || b != `{"id":"`+a.ID+`"}` {
		t.Errorf("consume = %d %s", code, b)
	}
	if code, _ := e.post(t, "/internal/confirmations/consume", consumeBody("alice", "delete_repo", args)); code != 404 {
		t.Errorf("second consume = %d", code)
	}
	// Declined.
	d := e.create(t, "alice", "delete_branch", args)
	if r, b := doAs(t, e.ppl, "alice", "POST", "/api/me/confirmations/"+d, `{"decision":"decline"}`); r.StatusCode != 200 || strings.TrimSpace(b) != `{"state":"declined"}` {
		t.Fatalf("decline = %d %s", r.StatusCode, b)
	}
	if code, b := e.post(t, "/internal/confirmations/consume", consumeBody("alice", "delete_branch", args)); code != 409 || b != `{"state":"declined"}` {
		t.Errorf("consume declined = %d %s", code, b)
	}

	// Refusals (G26).
	long := `{"x":"` + strings.Repeat("a", 4<<10) + `"}`
	other, _ := json.Marshal(map[string]string{"user": "alice", "client": "portcullis-ai-claude", "resource": "https://hub.example.org/mcp", "tool": "delete_repo",
		"args_sha256": sha(args), "args_preview": args, "reason": "destructive"})
	people, _ := json.Marshal(map[string]string{"user": "alice", "client": "portcullis-ai-claude", "resource": "https://people.example.org/mcp", "tool": "delete_repo",
		"args_sha256": sha(args), "args_preview": args, "reason": "destructive"})
	unknown, _ := json.Marshal(map[string]string{"user": "alice", "client": "portcullis-ai-claude", "resource": "https://nope.example.org/mcp", "tool": "delete_repo",
		"args_sha256": sha(args), "args_preview": args, "reason": "destructive"})
	mismatch, _ := json.Marshal(map[string]string{"user": "alice", "client": "portcullis-ai-claude", "resource": aiappResource, "tool": "delete_repo",
		"args_sha256": sha(`{}`), "args_preview": args, "reason": "confirm"})
	for _, c := range []struct {
		name, body string
		want       int
	}{
		{"not in the population", createBody("bob", "delete_repo", args, "confirm"), 403},
		{"unknown user", createBody("zed", "delete_repo", args, "confirm"), 403},
		{"admin resource", string(other), 404},
		{"people resource", string(people), 404},
		{"unknown resource", string(unknown), 404},
		{"not a confirm tool", createBody("alice", "create_repo", args, "confirm"), 400},
		{"bad reason", createBody("alice", "delete_repo", args, "maybe"), 400},
		{"digest mismatch", string(mismatch), 400},
		{"too long", createBody("alice", "delete_repo", long, "destructive"), 400},
		{"bad tool name", createBody("alice", "delete repo", args, "destructive"), 400},
		{"missing field", `{"user":"alice"}`, 400},
		{"case variant", strings.Replace(createBody("alice", "delete_repo", args, "confirm"), `"user"`, `"User"`, 1), 400},
	} {
		if code, b := e.post(t, "/internal/confirmations", c.body); code != c.want {
			t.Errorf("%s: %d %s, want %d", c.name, code, b, c.want)
		}
	}
	// A destructive-annotated tool the template doesn't list (the gate
	// passes the reason).
	if code, b := e.post(t, "/internal/confirmations", createBody("alice", "create_repo", args, "destructive")); code != 201 {
		t.Errorf("destructive = %d %s", code, b)
	}

	// Portcullis-resource confirmations (in process) are never consumed
	// through the internal API.
	pc, err := e.s.Hub.CreateConfirmation(directory.Actor{User: "alice", Via: directory.ViaAI, Client: "portcullis-ai-claude"}, confirm.Request{
		User: "alice", Client: "portcullis-ai-claude", Resource: "https://people.example.org/mcp", Tool: "delete_repo", ArgsSHA256: sha(args),
		ArgsPreview: args, Listener: confirm.ListenerPeople, Typed: "alice", Label: "your account"})
	if err != nil {
		t.Fatal(err)
	}
	if r, b := doAs(t, e.ppl, "alice", "POST", "/api/me/confirmations/"+pc.ID, decision("approve", "alice", "good-code")); r.StatusCode != 200 {
		t.Fatalf("approve portcullis = %d %s", r.StatusCode, b)
	}
	pbody, _ := json.Marshal(map[string]string{"user": "alice", "resource": "https://people.example.org/mcp", "tool": "delete_repo", "args_sha256": sha(args)})
	if code, b := e.post(t, "/internal/confirmations/consume", string(pbody)); code != 404 {
		t.Errorf("internal consume of a Portcullis confirmation = %d %s", code, b)
	}
	if c, err := e.s.Hub.ConsumeConfirmation(confirm.ListenerPeople, "alice", "https://people.example.org/mcp", "delete_repo", sha(args)); err != nil || c.ID != pc.ID {
		t.Errorf("in-process consume = %v %v", c, err)
	}

	// A Hub-listener confirmation with a companion's exact binding is never
	// matched by the internal consume (fix round 1): it stays approved.
	hargs := `{"name":"hub-bound"}`
	hc, err := e.s.Hub.CreateConfirmation(directory.Human("alice"), confirm.Request{User: "alice", Client: "portcullis-ai-claude",
		Resource: aiappResource, Tool: "delete_repo", ArgsSHA256: sha(hargs), ArgsPreview: hargs, Listener: confirm.ListenerHub, Typed: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if r, b := doAs(t, e.hub, "alice", "POST", "/api/me/confirmations/"+hc.ID, decision("approve", "x", "good-code")); r.StatusCode != 200 {
		t.Fatalf("hub approve = %d %s", r.StatusCode, b)
	}
	if code, b := e.post(t, "/internal/confirmations/consume", consumeBody("alice", "delete_repo", hargs)); code != 404 {
		t.Errorf("internal consume of a hub-listener confirmation = %d %s", code, b)
	}
	if c, err := e.s.Hub.ConsumeConfirmation(confirm.ListenerHub, "alice", aiappResource, "delete_repo", sha(hargs)); err != nil || c.ID != hc.ID {
		t.Errorf("it was consumed by the internal path: %v %v", c, err)
	}

	// The hourly limit (G27): 10 created per person, over both paths.
	// alice has created 5 (two companion, one destructive, two in process).
	for i := 0; i < 5; i++ {
		e.create(t, "alice", "delete_"+string(rune('a'+i)), args)
	}
	code, b = e.post(t, "/internal/confirmations", createBody("alice", "delete_z", args, "confirm"))
	if code != 429 || b != `{"code":"too_many"}` {
		t.Errorf("11th = %d %s", code, b)
	}
	au := e.confirmAudit(t)
	last := au[len(au)-1]
	if last.Result != "refused" || last.Actor != "alice" || last.Via != "ai" || last.Client != "portcullis-ai-claude" ||
		!strings.HasPrefix(last.Detail, "refused tool delete_z args_sha256 "+sha(args)) {
		t.Errorf("limit audit = %+v", last)
	}
	for _, x := range au {
		if strings.Contains(x.Detail, "repo-1") || strings.Contains(x.Target, "repo-1") {
			t.Errorf("an audit entry holds the arguments: %+v", x)
		}
	}
}

// TestConfirmPage (§15.6, §5.1): alice's id opened by bob → 404, on the
// Hub listener → 404, unknown → 404; by alice (any spelling of the id) →
// the Hub-rendered page with the tool, target, consequences and full
// arguments, escaped (a <script> argument is text), the typed check
// (the instance label, G75) and the fresh-auth parameters; no-store and
// no-referrer; no X-Forwarded-User → 401.
func TestConfirmPage(t *testing.T) {
	e := newConfirmEnv(t)
	args := `{"name":"<script>alert(1)</script>","note":"` + strings.Repeat("x", 3000) + `"}`
	id := e.create(t, "alice", "delete_repo", args)
	for _, c := range []struct {
		srv  *httptest.Server
		user string
		id   string
		want int
	}{
		{e.ppl, "bob", id, 404},
		{e.ppl, "alice", "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GG", 404},
		{e.ppl, "alice", "nope", 404},
		{e.hub, "alice", id, 404},
		{e.ppl, "", id, 401},
	} {
		if r, b := doAs(t, c.srv, c.user, "GET", "/confirm/"+c.id, ""); r.StatusCode != c.want || strings.Contains(b, "delete_repo") {
			t.Errorf("%s GET as %q = %d, want %d", c.srv.URL, c.user, r.StatusCode, c.want)
		}
	}
	for _, spelled := range []string{id, strings.ToLower(id), strings.ReplaceAll(id, "-", "")} {
		r, b := doAs(t, e.ppl, "Alice", "GET", "/confirm/"+spelled, "")
		if r.StatusCode != 200 || !strings.HasPrefix(r.Header.Get("Content-Type"), "text/html") || r.Header.Get("Cache-Control") != "no-store" ||
			r.Header.Get("Referrer-Policy") != "no-referrer" {
			t.Fatalf("alice GET = %d %v", r.StatusCode, r.Header)
		}
		framingHeaders(t, "people page", r.Header)
		for _, want := range []string{"delete_repo", "Tokens on AI App (aiapp.example.org)", "Runs delete_repo once on AI App (aiapp.example.org) as you",
			"AI App asks you to confirm every call of delete_repo.", "&lt;script&gt;alert(1)&lt;/script&gt;", strings.Repeat("x", 3000),
			`data-typed="AI App"`, `data-authorize-url="https://auth.example.org/realms/portcullis/protocol/openid-connect/auth"`,
			`data-redirect-uri="https://people.example.org/"`, `data-client-id="portcullis-fresh-auth"`, `data-id="` + id + `"`,
			"portcullis-ai-claude", `src="/static/confirm.js"`} {
			if !strings.Contains(b, want) {
				t.Errorf("page lacks %q", want)
			}
		}
		if strings.Contains(b, "<script>alert(1)") {
			t.Error("an argument is rendered as markup")
		}
	}
	// The handler itself: no user → 401 (forward-auth signs people in
	// before it; no special handling).
	w := httptest.NewRecorder()
	e.s.handleConfirmPage(w, httptest.NewRequest("GET", "/confirm/"+id, nil))
	if w.Code != 401 {
		t.Errorf("handler without X-Forwarded-User = %d", w.Code)
	}
	// The script is served on both listeners.
	for _, srv := range []*httptest.Server{e.ppl, e.hub} {
		if r, b := doAs(t, srv, "alice", "GET", "/static/confirm.js", ""); r.StatusCode != 200 || !strings.Contains(b, "portcullis-fresh-auth") {
			t.Errorf("%s confirm.js = %d", srv.URL, r.StatusCode)
		}
	}
	// A decided confirmation shows its state and offers nothing.
	doAs(t, e.ppl, "alice", "POST", "/api/me/confirmations/"+id, `{"decision":"decline"}`)
	if _, b := doAs(t, e.ppl, "alice", "GET", "/confirm/"+id, ""); !strings.Contains(b, `data-state="declined"`) || strings.Contains(b, `id="cf-approve"`) {
		t.Errorf("declined page offers a decision")
	}
}

// TestConfirmApprove (§15.6, §5.1, G11, G75): a wrong typed check → 409
// "type AI App to confirm", nothing recorded, no proof checked; a fresh
// proof (auth_time now − 10 s, amr hwk) → approved, audited ai.confirm
// approved with the digest, never the arguments; auth_time 301 s ago,
// amr file, a refused proof or a sign-in from more than 60 s before the
// request → 403 "a fresh passkey sign-in is required" (audited
// refused); a decline needs no passkey; a decided one → 409 {state};
// expiry audited expired by the sweeper.
func TestConfirmApprove(t *testing.T) {
	e := newConfirmEnv(t)
	// The refusal limiter's clock: each step below starts a new minute.
	var lmu sync.Mutex
	lnow := time.Now()
	e.s.Hub.SetEntryClockForTest(func() time.Time { lmu.Lock(); defer lmu.Unlock(); return lnow })
	nextMinute := func() { lmu.Lock(); lnow = lnow.Add(time.Minute); lmu.Unlock() }
	args := `{"name":"secret-repo-name"}`
	id := e.create(t, "alice", "delete_repo", args)
	post := func(id, body string) (int, string) {
		r, b := doAs(t, e.ppl, "alice", "POST", "/api/me/confirmations/"+id, body)
		return r.StatusCode, strings.TrimSpace(b)
	}
	// G75: the typed check is the instance label, not the companion's.
	for _, typed := range []string{"", "Tokens", "AI App · AI App", "ai app", "aiapp"} {
		if code, b := post(id, decision("approve", typed, "good-code")); code != 409 || b != "type AI App to confirm" {
			t.Errorf("typed %q = %d %s", typed, code, b)
		}
	}
	if e.people.n() != 0 {
		t.Error("a proof was checked before the typed check")
	}
	if code, b := e.post(t, "/internal/confirmations/consume", consumeBody("alice", "delete_repo", args)); code != 409 || b != `{"state":"pending"}` {
		t.Errorf("after refusals = %d %s", code, b)
	}
	// Stale or non-hardware proofs.
	nextMinute()
	for _, c := range []struct {
		name string
		at   time.Time
		amr  []string
		err  error
		code string
	}{
		{"301 s ago", time.Now().Add(-301 * time.Second), nil, nil, "good-code"},
		{"amr file", time.Time{}, []string{"file"}, nil, "good-code"},
		{"amr hwk+file", time.Time{}, []string{"hwk", "file"}, nil, "good-code"},
		{"amr pwd", time.Time{}, []string{"pwd"}, nil, "good-code"},
		{"before the request", time.Now().Add(-61 * time.Second), nil, nil, "good-code"},
		{"refused proof", time.Time{}, nil, nil, "bad-code"},
		{"verifier error", time.Time{}, nil, &freshauth.Error{Reason: "nonce mismatch"}, "good-code"},
	} {
		e.people.set(c.at, c.amr, c.err)
		if code, b := post(id, decision("approve", "AI App", c.code)); code != 403 || b != freshauth.Message {
			t.Errorf("%s = %d %s", c.name, code, b)
		}
	}
	refused := 0
	for _, a := range e.confirmAudit(t) {
		if a.Result == "refused" {
			refused++
		}
	}
	if refused != 5+7 {
		t.Errorf("%d refused audits, want 12", refused)
	}
	// Fresh: approved (the Hub listener's verifier is never asked).
	nextMinute()
	e.people.set(time.Now().Add(-10*time.Second), []string{"hwk"}, nil)
	hubCalls := e.hubFA.n()
	if code, b := post(id, decision("approve", " AI App ", "good-code")); code != 200 || b != `{"state":"approved"}` {
		t.Fatalf("approve = %d %s", code, b)
	}
	if e.hubFA.n() != hubCalls {
		t.Error("the Hub listener's verifier checked a people proof")
	}
	au := e.confirmAudit(t)
	last := au[len(au)-1]
	if last.Result != "ok" || last.Actor != "alice" || last.Via != "" || last.Target != aiappResource ||
		last.Detail != "approved tool delete_repo args_sha256 "+sha(args)+" confirmation "+id {
		t.Errorf("approve audit = %+v", last)
	}
	for _, a := range au {
		if strings.Contains(a.Detail+a.Target+a.Error, "secret-repo-name") {
			t.Errorf("audit holds the arguments: %+v", a)
		}
	}
	if code, b := post(id, decision("approve", "AI App", "good-code")); code != 409 || b != `{"state":"approved"}` {
		t.Errorf("again = %d %s", code, b)
	}
	// A sign-in 59 s before the request is still fine.
	id2 := e.create(t, "alice", "delete_tag", args)
	e.people.set(time.Now().Add(-59*time.Second), nil, nil)
	if code, b := post(id2, decision("approve", "AI App", "good-code")); code != 200 {
		t.Errorf("59 s before = %d %s", code, b)
	}
	// Decline: no passkey, no typed check.
	id3 := e.create(t, "alice", "delete_branch", args)
	n := e.people.n()
	if code, b := post(id3, `{"decision":"decline"}`); code != 200 || b != `{"state":"declined"}` {
		t.Errorf("decline = %d %s", code, b)
	}
	if e.people.n() != n {
		t.Error("a decline checked a proof")
	}
	if a := e.confirmAudit(t); a[len(a)-1].Detail != "declined tool delete_branch args_sha256 "+sha(args)+" confirmation "+id3 {
		t.Errorf("decline audit = %+v", a[len(a)-1])
	}
	if code, b := post(id3, `{"decision":"decline"}`); code != 409 || b != `{"state":"declined"}` {
		t.Errorf("decline again = %d %s", code, b)
	}
	// Bodies: 8 KiB, strict.
	for _, c := range []struct {
		body string
		want int
	}{
		{`{"decision":"maybe"}`, 400},
		{`{"decision":"decline","extra":1}`, 400},
		{`{"decision":"decline"} {}`, 400},
		{`{"decision":"approve","typed":"` + strings.Repeat("a", 9<<10) + `"}`, 413},
	} {
		if code, b := post(id2, c.body); code != c.want {
			t.Errorf("%.40s = %d %s, want %d", c.body, code, b, c.want)
		}
	}
	// Proofs can't be checked (the client not in place): 503, generic.
	id4 := e.create(t, "alice", "delete_note", args)
	e.s.Hub.SetFreshAuthReadyForTest(false)
	if code, b := post(id4, decision("approve", "AI App", "good-code")); code != 503 || strings.Contains(b, "in place") {
		t.Errorf("not ready = %d %s", code, b)
	}
	e.s.Hub.SetFreshAuthReadyForTest(true)

	// Expiry: audited expired by the sweeper; the page and the API show it.
	now := time.Now()
	var mu sync.Mutex
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	e.s.Hub.SetConfirmClockForTest(clock)
	id5 := e.create(t, "alice", "delete_old", args)
	mu.Lock()
	now = now.Add(10*time.Minute + time.Second)
	mu.Unlock()
	// Past its TTL: the page and the API show it expired at once.
	if code, b := post(id5, `{"decision":"decline"}`); code != 409 || b != `{"state":"expired"}` {
		t.Errorf("expired decline = %d %s", code, b)
	}
	if _, b := doAs(t, e.ppl, "alice", "GET", "/confirm/"+id5, ""); !strings.Contains(b, `data-state="expired"`) {
		t.Error("the page doesn't show expired")
	}
	// 20 min after creation a later create prunes the store: the expired
	// one is still swept, and audited exactly once.
	mu.Lock()
	now = now.Add(10 * time.Minute)
	mu.Unlock()
	e.create(t, "alice", "delete_newer", args)
	e.s.Hub.SweepConfirmations()
	e.s.Hub.SweepConfirmations()
	expired := 0
	for _, a := range e.confirmAudit(t) {
		if a.Detail == "expired tool delete_old args_sha256 "+sha(args)+" confirmation "+id5 && a.Actor == "hub" {
			expired++
		}
	}
	if expired != 1 {
		t.Errorf("%d expiry audits of %s, want exactly 1", expired, id5)
	}
}

// TestConfirmRefusalLimit (§5.1, G11): refused approvals count toward
// the per-caller refusal limit: the 11th attempt in a minute is 429.
func TestConfirmRefusalLimit(t *testing.T) {
	e := newConfirmEnv(t)
	id := e.create(t, "alice", "delete_repo", `{}`)
	for i := 0; i < 10; i++ {
		if r, _ := doAs(t, e.ppl, "alice", "POST", "/api/me/confirmations/"+id, decision("approve", "wrong", "good-code")); r.StatusCode != 409 {
			t.Fatalf("attempt %d = %d", i, r.StatusCode)
		}
	}
	if r, _ := doAs(t, e.ppl, "alice", "POST", "/api/me/confirmations/"+id, decision("approve", "AI App", "good-code")); r.StatusCode != 429 {
		t.Errorf("11th = %d, want 429", r.StatusCode)
	}
	// Admins on the Hub listener count refused approvals too.
	hc, err := e.s.Hub.CreateConfirmation(directory.Human("root"), confirm.Request{User: "root", Client: "portcullis-ai-claude",
		Resource: "https://hub.example.org/mcp", Tool: "delete_instance", ArgsSHA256: sha(`{}`), ArgsPreview: `{}`, Listener: confirm.ListenerHub, Typed: "grafana"})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		doAs(t, e.hub, "root", "POST", "/api/me/confirmations/"+hc.ID, decision("approve", "wrong", "good-code"))
	}
	if r, _ := doAs(t, e.hub, "root", "POST", "/api/me/confirmations/"+hc.ID, decision("approve", "grafana", "good-code")); r.StatusCode != 429 {
		t.Errorf("hub 11th = %d, want 429", r.StatusCode)
	}
}

// TestHubListenerConfirmRoutes (G12): the two confirmation routes are on
// the Hub listener exactly once; an admin confirmation is served there
// (with the Hub listener's verifier) and is 404 on people, and a
// people confirmation is 404 there; every Hub-listener answer is
// no-referrer, and index.html runs the popup callback.
func TestHubListenerConfirmRoutes(t *testing.T) {
	e := newConfirmEnv(t)
	n := map[string]int{}
	for _, p := range e.s.hubMux().patterns {
		n[p]++
	}
	for _, p := range []string{"GET /confirm/{id}", "POST /api/me/confirmations/{id}"} {
		if n[p] != 1 {
			t.Errorf("hub listener registers %q %d times, want 1", p, n[p])
		}
	}
	for p := range n {
		if strings.HasPrefix(p, "GET /api/me/ai") || strings.HasPrefix(p, "DELETE /api/me/ai") {
			t.Errorf("hub listener registers %q", p)
		}
	}
	args := `{"id":"grafana"}`
	hc, err := e.s.Hub.CreateConfirmation(directory.Actor{User: "root", Via: directory.ViaAI, Client: "portcullis-ai-claude"}, confirm.Request{
		User: "root", Client: "portcullis-ai-claude", Resource: "https://hub.example.org/mcp", Tool: "delete_instance", ArgsSHA256: sha(args),
		ArgsPreview: args, Listener: confirm.ListenerHub, Typed: "grafana", Label: "instance grafana",
		Consequences: []string{"Takes a backup, then permanently removes its containers"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := e.s.Hub.ConfirmationURL(hc); got != "https://hub.example.org/confirm/"+hc.ID {
		t.Errorf("url = %s", got)
	}
	if r, _ := doAs(t, e.ppl, "root", "GET", "/confirm/"+hc.ID, ""); r.StatusCode != 404 {
		t.Errorf("admin confirmation on people = %d", r.StatusCode)
	}
	if r, _ := doAs(t, e.ppl, "root", "POST", "/api/me/confirmations/"+hc.ID, `{"decision":"decline"}`); r.StatusCode != 404 {
		t.Errorf("admin decision on people = %d", r.StatusCode)
	}
	r, b := doAs(t, e.hub, "root", "GET", "/confirm/"+hc.ID, "")
	if r.StatusCode != 200 || r.Header.Get("Referrer-Policy") != "no-referrer" || !strings.Contains(b, "Takes a backup") ||
		!strings.Contains(b, `data-redirect-uri="https://hub.example.org/"`) {
		t.Fatalf("hub page = %d %v", r.StatusCode, r.Header)
	}
	framingHeaders(t, "hub page", r.Header)
	pid := e.create(t, "alice", "delete_repo", args)
	if r, _ := doAs(t, e.hub, "alice", "GET", "/confirm/"+pid, ""); r.StatusCode != 404 {
		t.Errorf("people confirmation on hub = %d", r.StatusCode)
	}
	pc := e.people.n()
	if r, b := doAs(t, e.hub, "root", "POST", "/api/me/confirmations/"+hc.ID, decision("approve", "grafana", "good-code")); r.StatusCode != 200 {
		t.Fatalf("hub approve = %d %s", r.StatusCode, b)
	}
	if e.hubFA.n() != 1 || e.people.n() != pc {
		t.Errorf("verifiers: hub %d people %d", e.hubFA.n(), e.people.n()-pc)
	}
	if c, err := e.s.Hub.ConsumeConfirmation(confirm.ListenerHub, "root", "https://hub.example.org/mcp", "delete_instance", sha(args)); err != nil || c.ID != hc.ID {
		t.Errorf("consume = %v %v", c, err)
	}
	// No-referrer on every Hub-listener answer; the callback in index.html.
	for _, p := range []string{"/", "/api/templates", "/healthz", "/nope"} {
		if r, _ := doAs(t, e.hub, "root", "GET", p, ""); r.Header.Get("Referrer-Policy") != "no-referrer" {
			t.Errorf("hub GET %s: Referrer-Policy %q", p, r.Header.Get("Referrer-Policy"))
		}
	}
	_, idx := doAs(t, e.hub, "root", "GET", "/", "")
	if !strings.Contains(idx, `<script src="/static/freshauth-callback.js"></script>`) {
		t.Error("index.html lacks the fresh-auth popup callback")
	}
	if !slices.Contains(e.s.peopleMux().patterns, "GET /confirm/{id}") {
		t.Error("people listener lacks the page")
	}
}

// TestConfirmPageScript (§5.1 "Fresh auth", §15.6): confirm.js runs the
// popup flow with every required parameter, accepts only a same-origin
// message from its own popup with the stored state, keeps the flow in
// sessionStorage only while it runs, and never writes markup.
func TestConfirmPageScript(t *testing.T) {
	js := webAsset(t, "confirm.js")
	// The flow is freshauth.js's (TestMyAppsFreshAuthOpener pins its
	// parameters and checks); confirm.js starts it with its own ctx and
	// posts the proof with the decision.
	for _, want := range []string{
		"PortcullisFreshAuth.start(fa, {",
		"ctx: { confirmation: id },",
		"send({ decision: 'approve', typed: t, code: p.code, code_verifier: p.code_verifier, nonce: p.nonce })",
		"send({ decision: 'decline' })",
		"PortcullisFreshAuth.cancel()",
		"root.dataset.authorizeUrl", "root.dataset.clientId", "root.dataset.redirectUri",
	} {
		if !strings.Contains(js, want) {
			t.Errorf("confirm.js lacks %q", want)
		}
	}
	for _, bad := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "localStorage", "sessionStorage", "eval(", "window.open("} {
		if strings.Contains(js, bad) {
			t.Errorf("confirm.js uses %s", bad)
		}
	}
	pg := webAsset(t, "confirm.html")
	if i, j := strings.Index(pg, `src="/static/freshauth.js"`), strings.Index(pg, `src="/static/confirm.js"`); i < 0 || j < 0 || i > j {
		t.Error("confirm.html must load freshauth.js before confirm.js")
	}
	// The CSP allows only same-origin scripts: no inline script on the page.
	if strings.Contains(pg, "<script>") {
		t.Error("confirm.html has an inline script (the CSP refuses it)")
	}
}

// Final review hub-mcp I3: bidi controls, zero-width and other invisible
// characters never reach the page raw — not in the arguments, the
// consequences, the target or the typed check — on both listeners; they
// are shown as \uXXXX. M1: a companion preview that isn't canonical JSON
// is refused (400).
func TestConfirmPageShowsInvisibleCharacters(t *testing.T) {
	e := newConfirmEnv(t)
	const rlo, zwj, lri = "\u202e", "\u200d", "\u2066"
	hidden := []string{rlo, zwj, lri, "\u200b", "\ufeff", "\u00a0"}
	noneRaw := func(where, body string) {
		t.Helper()
		for _, h := range hidden {
			if strings.Contains(body, h) {
				t.Errorf("%s: raw %U on the page", where, []rune(h)[0])
			}
		}
	}
	// A companion confirmation: the gate's canonical preview (JCS keeps
	// U+202E and U+200D raw).
	args := `{"name":"repo` + rlo + `1-txt.exe` + zwj + `"}`
	id := e.create(t, "alice", "delete_repo", args)
	r, b := doAs(t, e.ppl, "alice", "GET", "/confirm/"+id, "")
	if r.StatusCode != 200 {
		t.Fatalf("page = %d", r.StatusCode)
	}
	noneRaw("companion page", b)
	if !strings.Contains(b, `\u202E`) || !strings.Contains(b, `\u200D`) {
		t.Errorf("companion page doesn't show the escapes: %s", b)
	}
	// A Portcullis tool's confirmation: consequences and label too.
	hargs := `{"command":"echo ok #` + rlo + `mr- fr- mr","id":"grafana"}`
	hc, err := e.s.Hub.CreateConfirmation(directory.Actor{User: "root", Via: directory.ViaAI, Client: "portcullis-ai-claude"}, confirm.Request{
		User: "root", Client: "portcullis-ai-claude", Resource: "https://hub.example.org/mcp", Tool: "exec", ArgsSHA256: sha(hargs),
		ArgsPreview: hargs, Listener: confirm.ListenerHub, Typed: "grafana", Label: "instance graf" + zwj + "ana",
		Consequences: []string{"Runs echo ok #" + rlo + "mr- fr- mr in grafana" + lri + "."}})
	if err != nil {
		t.Fatal(err)
	}
	r, b = doAs(t, e.hub, "root", "GET", "/confirm/"+hc.ID, "")
	if r.StatusCode != 200 {
		t.Fatalf("hub page = %d", r.StatusCode)
	}
	noneRaw("hub page", b)
	if !strings.Contains(b, `echo ok #\u202Emr- fr- mr in grafana\u2066.`) || !strings.Contains(b, `graf\u200Dana`) {
		t.Errorf("hub page doesn't show the escapes: %s", b)
	}
	v, err := e.s.Hub.ConfirmationPage(hub.ListenerHub, hc.ID, "root")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range append([]string{v.Arguments, v.Target, v.Typed, v.Tool}, v.Consequences...) {
		noneRaw("view", s)
	}
	if got := hub.VisibleText("a\\b" + "\U000E0001" + " c"); got != `a\b\U000E0001 c` {
		t.Errorf("VisibleText = %q", got)
	}
	// M1: not the canonical form.
	for _, p := range []string{`{"b":1,"a":2}`, `{"a":1,"a":2}`, `{ "a":1}`, `{"a":1.0}`} {
		if code, b := e.post(t, "/internal/confirmations", createBody("alice", "delete_repo", p, "confirm")); code != 400 {
			t.Errorf("preview %s = %d %s, want 400", p, code, b)
		}
	}
}
