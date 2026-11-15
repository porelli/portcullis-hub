// Package mailctltest is an in-memory mailctl API (contract §19.5) for
// the Hub's tests: a real HTTP server the real mailctl.Client talks to,
// built from the contract (not from core's code): bearer check, strict
// bodies, generation and mass-removal refusals, state.Parse's refusals,
// the 5-password limit and Stalwart's per-account id reuse (the next id
// is the highest + 1).
package mailctltest

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/mailctl"
)

// Secret is the fake's bearer secret.
const Secret = "mailctltest-hub-secret-0123456789abcdefghij"

// Server is the fake mailctl.
type Server struct {
	t   *testing.T
	srv *httptest.Server

	mu sync.Mutex
	// Doc is the last accepted document (nil: none yet); Applied its
	// applied generation. HoldApply: accepted documents aren't applied
	// (GET /v1/state keeps the old applied_generation).
	Doc       *mailctl.MailState
	Docs      []mailctl.MailState // every accepted document, in order
	Applied   int
	HoldApply bool
	Bootstrap bool
	// Down: every request answers 503 "mail server unreachable".
	Down bool
	// PutErr: PUT /v1/state answers it (status, message) instead.
	PutStatus int
	PutMsg    string
	// DNSSets: domain → its wanted records (default: one MX).
	DNSSets  map[string]mailctl.DNSSet
	ChecksV  mailctl.Checks
	StatusV  mailctl.Status
	ActionV  map[string]int // action name → status (default 202)
	Actions  []string       // "<name> <domain>"
	Requests []string       // "<METHOD> <path>"
	// Wildcards: domain → the last ?wildcard= of GET /v1/dns/{domain}.
	Wildcards map[string]string
	// creds: username → its live passwords; nextNow the clock.
	creds map[string][]fakeCred
	Now   func() time.Time
	// Created: every secret handed out (tests grep logs and state for them).
	Created []string
	// RevokeStatus: DELETE /v1/credentials answers it instead (0: 204).
	RevokeStatus int
	// Deletes: every DELETE /v1/credentials ("<uuid> <id>").
	Deletes []string
	// OmitRemoved: the mass-removal 409 carries no "removed" list.
	OmitRemoved bool
	// RevokeOK: DELETE answers 200 instead of 204 (a non-204 success).
	RevokeOK bool
}

type fakeCred struct {
	mailctl.Credential
}

// New starts a fake (closed with t's cleanup).
func New(t *testing.T) *Server {
	s := &Server{t: t, Bootstrap: true, DNSSets: map[string]mailctl.DNSSet{}, ActionV: map[string]int{}, creds: map[string][]fakeCred{},
		Now: func() time.Time { return time.Now().UTC().Truncate(time.Second) }}
	s.ChecksV = mailctl.Checks{CheckedAt: time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC), Checks: []mailctl.Check{}}
	s.StatusV = mailctl.Status{Bootstrap: true, StalwartVersion: "1.1.0", DKIM: []mailctl.StatusDKIM{}, MTASTS: []mailctl.StatusMTASTS{},
		DMARC: []mailctl.StatusDMARC{}, ClientIP: "preserved", Former: []mailctl.StatusFormer{}, Cert: mailctl.StatusCert{SANs: []string{}}}
	s.srv = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.srv.Close)
	return s
}

// URL is the fake's base URL.
func (s *Server) URL() string { return s.srv.URL }

// SecretFile writes the bearer secret into a temp file.
func (s *Server) SecretFile() string {
	f := filepath.Join(s.t.TempDir(), "hub-secret")
	if err := os.WriteFile(f, []byte(Secret+"\n"), 0600); err != nil {
		s.t.Fatal(err)
	}
	return f
}

// Client is a real mailctl.Client on the fake.
func (s *Server) Client() *mailctl.Client { return mailctl.New(s.URL(), s.SecretFile()) }

// Close stops the server (connections then fail: unreachable).
func (s *Server) Close() { s.srv.Close() }

// Lock runs f under the fake's lock (tests change knobs).
func (s *Server) Lock(f func(s *Server)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f(s)
}

// Puts is the number of accepted documents.
func (s *Server) Puts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.Docs)
}

// Last is a copy of the last accepted document (nil: none).
func (s *Server) Last() *mailctl.MailState {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Doc == nil {
		return nil
	}
	d := *s.Doc
	return &d
}

// Creds are user's live passwords.
func (s *Server) Creds(user string) []mailctl.Credential {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []mailctl.Credential
	for _, c := range s.creds[user] {
		out = append(out, c.Credential)
	}
	return out
}

// DropCreds destroys every password of user (a restore's voiding).
func (s *Server) DropCreds(user string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.creds, user)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func errJSON(w http.ResponseWriter, status int, format string, a ...any) {
	writeJSON(w, status, map[string]string{"error": fmt.Sprintf(format, a...)})
}

func strict(r *http.Request, v any) error {
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(http.MaxBytesReader(nil, r.Body, 4<<20)); err != nil {
		return err
	}
	dec := json.NewDecoder(&buf)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return fmt.Errorf("trailing data")
	}
	return nil
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if subtle.ConstantTimeCompare([]byte(auth), []byte("Bearer "+Secret)) != 1 {
		w.WriteHeader(403)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Requests = append(s.Requests, r.Method+" "+r.URL.Path)
	if s.Down {
		errJSON(w, 503, "mail server unreachable")
		return
	}
	switch p := r.URL.Path; {
	case p == "/v1/state" && r.Method == http.MethodPut:
		s.putState(w, r)
	case p == "/v1/state" && r.Method == http.MethodGet:
		gen := 0
		if s.Doc != nil {
			gen = s.Doc.Generation
		}
		writeJSON(w, 200, mailctl.StateStatus{Generation: gen, AppliedGeneration: s.Applied, Bootstrap: s.Bootstrap, Errors: []string{}})
	case strings.HasPrefix(p, "/v1/dns/") && r.Method == http.MethodGet:
		d := strings.TrimPrefix(p, "/v1/dns/")
		wc := r.URL.Query().Get("wildcard")
		if wc != "true" && wc != "false" {
			errJSON(w, 400, "wildcard must be true or false")
			return
		}
		if s.Wildcards == nil {
			s.Wildcards = map[string]string{}
		}
		s.Wildcards[d] = wc
		if !s.mailDomain(d) {
			errJSON(w, 404, "%s is not a mail domain", d)
			return
		}
		set, ok := s.DNSSets[d]
		if !ok {
			set = mailctl.DNSSet{Domain: d, Records: []mailctl.Record{{Name: d, Type: "MX", TTL: 3600, Value: "10 mail.example.org."}}, DKIM: "auto", TLSA: "withheld: dnssec unsigned"}
		}
		writeJSON(w, 200, set)
	case p == "/v1/checks" && r.Method == http.MethodGet:
		writeJSON(w, 200, s.ChecksV)
	case p == "/v1/status" && r.Method == http.MethodGet:
		writeJSON(w, 200, s.StatusV)
	case p == "/v1/credentials" && r.Method == http.MethodGet:
		u := r.URL.Query().Get("user")
		if !s.account(u) {
			errJSON(w, 404, "no such account")
			return
		}
		out := []mailctl.Credential{}
		for _, c := range s.creds[u] {
			out = append(out, c.Credential)
		}
		writeJSON(w, 200, out)
	case p == "/v1/credentials" && r.Method == http.MethodPost:
		s.createCred(w, r)
	case strings.HasPrefix(p, "/v1/credentials/") && r.Method == http.MethodDelete:
		q := r.URL.Query()
		if len(q) != 1 || q.Get("uuid") == "" {
			errJSON(w, 400, "the query must be exactly ?uuid=")
			return
		}
		s.Deletes = append(s.Deletes, q.Get("uuid")+" "+strings.TrimPrefix(p, "/v1/credentials/"))
		u := s.userOfUUID(q.Get("uuid"))
		if u == "" {
			w.WriteHeader(204) // unknown (or parked) account: nothing here
			return
		}
		if s.RevokeStatus != 0 {
			errJSON(w, s.RevokeStatus, "mail server unreachable")
			return
		}
		if s.RevokeOK {
			w.WriteHeader(200)
			return
		}
		id := strings.TrimPrefix(p, "/v1/credentials/")
		keep := s.creds[u][:0]
		for _, c := range s.creds[u] {
			if c.ID != id {
				keep = append(keep, c)
			}
		}
		s.creds[u] = keep
		w.WriteHeader(204)
	case strings.HasPrefix(p, "/v1/actions/") && r.Method == http.MethodPost:
		name := strings.TrimPrefix(p, "/v1/actions/")
		var body struct {
			Domain string `json:"domain"`
		}
		if err := strict(r, &body); err != nil {
			errJSON(w, 400, "bad body")
			return
		}
		if !s.mailDomain(body.Domain) {
			errJSON(w, 404, "%s is not a mail domain", body.Domain)
			return
		}
		s.Actions = append(s.Actions, name+" "+body.Domain)
		if st := s.ActionV[name]; st != 0 && st != 202 {
			errJSON(w, st, "nothing to do")
			return
		}
		w.WriteHeader(202)
	default:
		errJSON(w, 404, "not found")
	}
}

func (s *Server) mailDomain(d string) bool {
	if s.Doc == nil {
		return false
	}
	for _, x := range s.Doc.Domains {
		if x.Name == d {
			return true
		}
	}
	return false
}

// userOfUUID is the username of the account with uuid ("" = none).
func (s *Server) userOfUUID(uuid string) string {
	if s.Doc == nil {
		return ""
	}
	for _, a := range s.Doc.Accounts {
		if a.UUID == uuid {
			return a.Username
		}
	}
	return ""
}

// uuidOf is u's uuid in the applied document ("" = none).
func (s *Server) uuidOf(u string) string {
	if s.Doc == nil {
		return ""
	}
	for _, a := range s.Doc.Accounts {
		if a.Username == u {
			return a.UUID
		}
	}
	return ""
}

func (s *Server) account(u string) bool {
	if s.Doc == nil {
		return false
	}
	for _, a := range s.Doc.Accounts {
		if a.Username == u {
			return true
		}
	}
	return false
}

var (
	usernameRe = regexp.MustCompile(`^[a-z0-9_.@-]{1,64}$`)
	uuidRe     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// parse is state.Parse's refusals (contract §19.5).
func parse(d *mailctl.MailState) error {
	if d.Version != 1 {
		return fmt.Errorf("version %d", d.Version)
	}
	doms := map[string]bool{}
	for _, x := range d.Domains {
		if x.Mail != mailctl.MailOn && x.Mail != mailctl.MailOff && x.Mail != mailctl.MailDraining {
			return fmt.Errorf("domain %s: mail %q", x.Name, x.Mail)
		}
		if x.DMARCStart != "reject" && x.DMARCStart != "none" {
			return fmt.Errorf("domain %s: dmarc_start %q", x.Name, x.DMARCStart)
		}
		doms[x.Name] = true
	}
	if !doms[d.PrimaryDomain] {
		return fmt.Errorf("primary domain %s not in domains", d.PrimaryDomain)
	}
	used := map[string]string{}
	use := func(addr, owner string) error {
		local, dom, ok := strings.Cut(addr, "@")
		if !ok || !doms[dom] {
			return fmt.Errorf("address %s is not on a mail domain", addr)
		}
		for _, r := range mailctl.ReservedLocalParts {
			if local == r {
				return fmt.Errorf("address %s is reserved", addr)
			}
		}
		if o, ok := used[addr]; ok {
			return fmt.Errorf("address %s used by %s and %s", addr, o, owner)
		}
		used[addr] = owner
		return nil
	}
	accts := map[string]bool{}
	for _, a := range d.Accounts {
		if !usernameRe.MatchString(a.Username) || !uuidRe.MatchString(a.UUID) || a.QuotaBytes < 0 || len(a.Addresses) == 0 {
			return fmt.Errorf("account %q", a.Username)
		}
		if a.Addresses[0] != a.Username+"@"+d.PrimaryDomain {
			return fmt.Errorf("account %s: first address %s", a.Username, a.Addresses[0])
		}
		accts[a.Username] = true
		for _, x := range a.Addresses {
			if err := use(x, a.Username); err != nil {
				return err
			}
		}
	}
	for _, x := range d.Aliases {
		if !accts[x.Username] {
			return fmt.Errorf("alias %s: %s is no account", x.Address, x.Username)
		}
		if err := use(x.Address, "alias of "+x.Username); err != nil {
			return err
		}
	}
	for _, l := range d.Lists {
		if l.Posting != "members" && l.Posting != "anyone" {
			return fmt.Errorf("list %s: posting %q", l.Address, l.Posting)
		}
		for _, m := range l.Members {
			if !accts[m] {
				return fmt.Errorf("list %s: %s is no account", l.Address, m)
			}
		}
		if err := use(l.Address, "list"); err != nil {
			return err
		}
	}
	for _, p := range d.Postmaster {
		if !accts[p] {
			return fmt.Errorf("postmaster %s is no account", p)
		}
	}
	if d.Limits.RecipientsPerHour < 1 || d.Limits.RecipientsPerHour > 100000 || d.Limits.RecipientsPerDay < 1 || d.Limits.RecipientsPerDay > 100000 {
		return fmt.Errorf("limits")
	}
	if d.Spam.JunkScore < 1 || d.Spam.JunkScore >= d.Spam.RejectScore || d.Spam.RejectScore > 100 {
		return fmt.Errorf("scores")
	}
	if d.Aliases == nil || d.Lists == nil || d.Postmaster == nil || d.LocalNetworks == nil || d.Domains == nil || d.Accounts == nil || d.Spam.Allow == nil || d.Spam.Block == nil {
		return fmt.Errorf("missing key")
	}
	return nil
}

func (s *Server) putState(w http.ResponseWriter, r *http.Request) {
	// Every key present: decode into raw first.
	var raw map[string]json.RawMessage
	body := new(bytes.Buffer)
	body.ReadFrom(r.Body)
	if err := json.Unmarshal(body.Bytes(), &raw); err != nil {
		errJSON(w, 400, "not JSON")
		return
	}
	for _, k := range []string{"version", "generation", "primary_domain", "confirm_mass_removal", "domains", "accounts", "aliases", "lists", "postmaster", "limits", "spam", "local_networks"} {
		if _, ok := raw[k]; !ok {
			errJSON(w, 400, "missing key %s", k)
			return
		}
	}
	var d mailctl.MailState
	dec := json.NewDecoder(bytes.NewReader(body.Bytes()))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		errJSON(w, 400, "bad document: %v", err)
		return
	}
	if s.PutStatus != 0 {
		errJSON(w, s.PutStatus, "%s", s.PutMsg)
		return
	}
	if err := parse(&d); err != nil {
		errJSON(w, 400, "%v", err)
		return
	}
	if s.Doc != nil && d.Generation <= s.Doc.Generation {
		errJSON(w, 409, "generation %d is not greater than %d", d.Generation, s.Doc.Generation)
		return
	}
	if s.Doc != nil && len(s.Doc.Accounts) > 0 {
		now := map[string]bool{}
		for _, a := range d.Accounts {
			now[a.UUID] = true
		}
		gone := 0
		removed := []map[string]string{}
		for _, a := range s.Doc.Accounts {
			if !now[a.UUID] {
				gone++
				removed = append(removed, map[string]string{"username": a.Username, "uuid": a.UUID})
			}
		}
		if gone*2 > len(s.Doc.Accounts) && !d.ConfirmMassRemoval {
			body := map[string]any{"error": fmt.Sprintf("mass removal: %d of %d accounts", gone, len(s.Doc.Accounts)), "error_kind": "mass_removal"}
			if !s.OmitRemoved {
				body["removed"] = removed
			}
			writeJSON(w, 409, body)
			return
		}
	}
	// A removed account loses every password first (M4).
	keep := map[string]bool{}
	for _, a := range d.Accounts {
		keep[a.Username] = true
	}
	for u := range s.creds {
		if !keep[u] {
			delete(s.creds, u)
		}
	}
	s.Doc = &d
	s.Docs = append(s.Docs, d)
	if !s.HoldApply {
		s.Applied = d.Generation
	}
	writeJSON(w, 202, map[string]int{"generation": d.Generation})
}

// Apply marks the last document applied (after HoldApply).
func (s *Server) Apply() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Doc != nil {
		s.Applied = s.Doc.Generation
	}
}

func (s *Server) createCred(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username  string     `json:"username"`
		UUID      string     `json:"uuid"`
		Label     string     `json:"label"`
		ExpiresAt *time.Time `json:"expires_at"`
	}
	if err := strict(r, &body); err != nil {
		errJSON(w, 400, "bad body")
		return
	}
	now := s.Now()
	if n := len([]rune(body.Label)); n < 1 || n > 64 || strings.ContainsAny(body.Label, "\r\n") {
		errJSON(w, 400, "label must be 1–64 characters on one line")
		return
	}
	if body.ExpiresAt != nil && !body.ExpiresAt.After(now) {
		errJSON(w, 400, "expires_at is in the past")
		return
	}
	if !s.account(body.Username) {
		errJSON(w, 404, "no such account")
		return
	}
	if body.UUID != s.uuidOf(body.Username) {
		writeJSON(w, 409, map[string]string{"error": "the account has another uuid", "error_kind": "account_mismatch"})
		return
	}
	cs := s.creds[body.Username]
	if len(cs) >= mailctl.MaxActivePasswords {
		errJSON(w, 409, "5 active mail passwords")
		return
	}
	// Stalwart: the next id is the highest + 1 (reused once the highest
	// is destroyed).
	next := 1
	for _, c := range cs {
		if n, _ := strconv.Atoi(c.ID); n >= next {
			next = n + 1
		}
	}
	sec := fmt.Sprintf("mailpw-%s-%d-%d", body.Username, next, now.UnixNano())
	c := fakeCred{mailctl.Credential{ID: strconv.Itoa(next), Label: body.Label, CreatedAt: now, ExpiresAt: body.ExpiresAt}}
	s.creds[body.Username] = append(cs, c)
	sort.Slice(s.creds[body.Username], func(i, j int) bool { return s.creds[body.Username][i].ID < s.creds[body.Username][j].ID })
	s.Created = append(s.Created, sec)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 201, map[string]any{"id": c.ID, "secret": sec, "created_at": now, "expires_at": body.ExpiresAt})
}
