package hub

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/aigate"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/state"
)

// Plan 4 Task 15: per-instance AI support follows hostname changes,
// backups, restore, restore-as and delete (contract §8 "Follows the
// resource", §11.3–§11.6, §15.11).

const (
	tokScope   = "mcp:aiapp.tok"
	hdrScope   = "mcp:aiapp.hdr"
	movedTok   = "https://tools.example.com/mcp"
	movedHdr   = "https://tools.example.com/hdr/mcp"
	oldHdrURL  = "https://aiapp.example.com/hdr/mcp"
	credMarker = "cred-marker-9f3e1c7a"
)

// newLifecycleFixture: aiapp enabled with tok (read_write) and hdr on,
// both scopes in Keycloak.
func newLifecycleFixture(t *testing.T, mutate ...func(map[string][2]string)) *instAIFixture {
	t.Helper()
	a := newInstAIFixture(t, func(st *state.AppState) {
		st.AIInstances = map[string]state.AIInstance{"aiapp": {Companions: map[string]state.AICompanion{
			"tok": {Enabled: true, Mode: "read_write"},
			"hdr": {Enabled: true, Mode: "read_only"},
		}}}
	}, mutate...)
	a.h.lockPoll = 5 * time.Millisecond
	a.enable(t, "aiapp")
	a.setMintAnswer(nil)
	if err := a.h.syncAIScopes(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{tokScope, hdrScope} {
		if _, ok := a.kc.scope(s); !ok {
			t.Fatalf("scope %s missing before the test", s)
		}
	}
	return a
}

func (a *instAIFixture) wantScope(t *testing.T, name, audience, host string) {
	t.Helper()
	s, ok := a.kc.scope(name)
	if !ok {
		t.Errorf("scope %s missing", name)
		return
	}
	if s.Audience != audience || s.ConsentText != "Use AI App ("+host+") as you" {
		t.Errorf("scope %s = %+v, want audience %s and the consent text naming %s", name, s, audience, host)
	}
}

// TestSetHostsMovesMCPResource (Review Focus 4): the scopes' audience and
// consent text move in the Keycloak step (undone with the redirect URIs
// on a later failure); router rule, gate file and MyApps follow the state.
func TestSetHostsMovesMCPResource(t *testing.T) {
	// aiapp with a Keycloak client on its router (fix round 1): the
	// redirect URIs and the forward-auth callbacks move and come back
	// with the scopes.
	a := newLifecycleFixture(t, func(extra map[string][2]string) {
		m := extra["aiapp"]
		m[0] = strings.Replace(m[0], "env:\n", "keycloak_clients:\n  - client_id: aiapp\n    redirect_uri: https://{{HOST_AIAPP}}/cb\nenv:\n", 1)
		extra["aiapp"] = m
	})
	doms := &fakeDomains{}
	doms.set(Domain{Name: "example.net", State: DomainReady})
	a.h.SetDomainSource(doms)
	envDir := filepath.Dir(a.h.envPath("aiapp"))
	const extraHost = "tools.example.net"
	newCB := keycloak.CallbackURI(extraHost)
	// keycloakBack: the last Keycloak calls moved the client and the
	// callbacks back to the old host.
	keycloakBack := func(phase string) {
		t.Helper()
		a.idp.mu.Lock()
		defer a.idp.mu.Unlock()
		hu, cb := a.idp.hostUpdates, a.idp.callbacks
		if len(hu) < 2 || hu[len(hu)-2] != "aiapp:https://aiapp.example.com/cb -> https://"+extraHost+"/cb" ||
			hu[len(hu)-1] != "aiapp:https://"+extraHost+"/cb -> https://aiapp.example.com/cb" {
			t.Errorf("%s: client host updates = %q", phase, hu)
		}
		if len(cb) < 2 || cb[len(cb)-2] != "+"+newCB+" -" || cb[len(cb)-1] != "+ -"+newCB {
			t.Errorf("%s: callbacks = %q", phase, cb)
		}
	}

	// A failure after the Keycloak step (the env can't be rewritten):
	// both scopes, the client and the callbacks are moved back.
	if err := os.Chmod(envDir, 0o500); err != nil {
		t.Fatal(err)
	}
	err := a.h.SetHosts("aiapp", map[string]string{"aiapp": extraHost}, root)
	os.Chmod(envDir, 0o755)
	if statusOf(err) != 500 || !strings.Contains(err.Error(), "nothing changed") {
		t.Fatalf("file failure = %v", err)
	}
	keycloakBack("commit failure")
	a.wantScope(t, tokScope, tokResource, "aiapp.example.com")
	a.wantScope(t, hdrScope, oldHdrURL, "aiapp.example.com")
	moved := 0
	a.kc.mu.Lock()
	for _, c := range a.kc.calls {
		if c == "ensure:"+tokScope {
			moved++
		}
	}
	a.kc.mu.Unlock()
	if moved < 2 {
		t.Errorf("tok's scope ensured %d times, want moved and moved back", moved)
	}

	// A scope that can't be moved: the change stops in the Keycloak step,
	// the scope moved first is moved back.
	a.kc.mu.Lock()
	a.kc.failEnsure = map[string]error{tokScope: errors.New("keycloak down")}
	a.kc.mu.Unlock()
	err = a.h.SetHosts("aiapp", map[string]string{"aiapp": extraHost}, root)
	if statusOf(err) != 502 || !strings.Contains(err.Error(), tokScope) {
		t.Fatalf("scope failure = %v", err)
	}
	a.wantScope(t, hdrScope, oldHdrURL, "aiapp.example.com")
	a.wantScope(t, tokScope, tokResource, "aiapp.example.com")
	keycloakBack("scope failure")
	if a.h.Template("aiapp").Hosts["aiapp"] != "aiapp.example.com" {
		t.Error("hostnames changed after a failed scope step")
	}
	a.kc.mu.Lock()
	a.kc.failEnsure = nil
	a.kc.mu.Unlock()

	if err := a.h.SetHosts("aiapp", map[string]string{"aiapp": "tools.example.com"}, root); err != nil {
		t.Fatal(err)
	}
	a.h.Wait()
	a.wantScope(t, tokScope, movedTok, "tools.example.com")
	a.wantScope(t, hdrScope, movedHdr, "tools.example.com")
	if got := a.kc.opt("portcullis-ai-claude"); !slices.Contains(got, tokScope) || !slices.Contains(got, hdrScope) {
		t.Errorf("claude's optional scopes = %v", got)
	}

	ov := a.override(t, "aiapp")
	if !strings.Contains(ov, `"`+tokOverrideMCP+"rule\": \"Host(`tools.example.com`)") {
		t.Errorf("router rule not on the new host:\n%s", ov)
	}
	if strings.Contains(ov, "aiapp.example.com") {
		t.Errorf("override still names the old host:\n%s", ov)
	}
	g := a.gate(t)
	if resourceByURL(g, movedTok) == nil || resourceByURL(g, movedHdr) == nil {
		t.Errorf("gate resources = %v", urls(g))
	}
	if resourceByURL(g, tokResource) != nil || resourceByURL(g, oldHdrURL) != nil {
		t.Errorf("gate still lists the old URLs: %v", urls(g))
	}
	// My apps lists this app only once it has per-person parts (its AI
	// card is Task 21's, built from the gate's resources above); the
	// portal entry it links to follows the state.
	portal, err := os.ReadFile(a.h.portalPath())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(portal), "https://tools.example.com") || strings.Contains(string(portal), "aiapp.example.com") {
		t.Errorf("portal-apps.json = %s", portal)
	}
}

// archiveMembers reads an archive's members.
func archiveMembers(t *testing.T, a *instAIFixture, archive string) (map[string][]byte, []byte) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(a.h.backupsDir(), filepath.FromSlash(archive)))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]byte{}
	tr := tar.NewReader(bytes.NewReader(raw))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		out[hdr.Name] = b
	}
	return out, raw
}

// rewriteArchiveMember replaces (or adds) member in archive, keeping
// MANIFEST.json's sha256 right.
func rewriteArchiveMember(t *testing.T, a *instAIFixture, archive, member string, data []byte) {
	t.Helper()
	members, _ := archiveMembers(t, a, archive)
	var m BackupManifest
	if err := json.Unmarshal(members[manifestMember], &m); err != nil {
		t.Fatal(err)
	}
	members[member] = data
	sum := sha256.Sum256(data)
	m.Files[member] = hex.EncodeToString(sum[:])
	mb, _ := json.Marshal(m)
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	names := []string{manifestMember}
	for n := range members {
		if n != manifestMember {
			names = append(names, n)
		}
	}
	slices.Sort(names[1:])
	members[manifestMember] = mb
	for _, n := range names {
		if err := tw.WriteHeader(&tar.Header{Name: n, Mode: 0o600, Size: int64(len(members[n])), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write(members[n])
	}
	tw.Close()
	if err := os.WriteFile(filepath.Join(a.h.backupsDir(), filepath.FromSlash(archive)), buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestBackupCarriesAIConfig: config/ai.json is the instance's AI state
// (switches, modes, providers), listed with its sha256; no credential,
// no internal flag, nothing of the credential store in the tar.
func TestBackupCarriesAIConfig(t *testing.T) {
	a := newLifecycleFixture(t)
	if err := a.h.creds().Put(aigate.Credential{Instance: "aiapp", Companion: "tok", User: "alice", ID: "id-marker-41d2", MintedAt: aigate.At(time.Now())}, []byte(credMarker)); err != nil {
		t.Fatal(err)
	}
	a.h.mu.Lock()
	ai := a.h.st.AIInstances["aiapp"]
	tok := ai.Companions["tok"]
	tok.OnChangePending, tok.IdentityMode, tok.RevokeHook = true, "app_token", "tok-revoke"
	ai.Companions["tok"] = tok
	ai.Providers = []string{"openai-main"}
	a.h.st.AIInstances["aiapp"] = ai
	a.h.mu.Unlock()

	entry, err := a.h.BackupInstance("aiapp", root)
	if err != nil {
		t.Fatal(err)
	}
	members, raw := archiveMembers(t, a, entry.Archive)
	got, ok := members[aiMember]
	if !ok {
		t.Fatalf("no %s in %v", aiMember, slices.Sorted(func(yield func(string) bool) {
			for k := range members {
				if !yield(k) {
					return
				}
			}
		}))
	}
	want := `{"companions":{"hdr":{"enabled":true,"mode":"read_only"},"tok":{"enabled":true,"mode":"read_write"}},"providers":["openai-main"]}`
	if strings.TrimSpace(string(got)) != want {
		t.Errorf("%s = %s, want %s", aiMember, got, want)
	}
	var m BackupManifest
	if err := json.Unmarshal(members[manifestMember], &m); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(got)
	if m.Files[aiMember] != hex.EncodeToString(sum[:]) {
		t.Errorf("MANIFEST lists %s as %q", aiMember, m.Files[aiMember])
	}
	credFile, _ := os.ReadFile(a.h.creds().path)
	for _, marker := range []string{credMarker, "id-marker-41d2", "revoke_pending", "on_change_pending", "identity_mode", "revoke_hook", "mcp-credentials", string(credFile)} {
		if marker != "" && bytes.Contains(raw, []byte(marker)) {
			t.Errorf("archive holds %q", clip(marker, 40))
		}
	}
	// The archive restores (the member is accepted by the checks).
	if _, err := a.h.RestoreInstance("aiapp", entry.Archive, root); err != nil {
		t.Fatal(err)
	}
}

// TestRestoreRevokesAllFirst: a same-instance restore deletes the
// instance's entries, puts config/ai.json back and runs revoke_all in the
// restored app before the gate lists the companion again; a failing
// revoke_all keeps it out (switched off), with the error shown.
func TestRestoreRevokesAllFirst(t *testing.T) {
	a := newLifecycleFixture(t)
	if _, err := a.h.MintCredential(context.Background(), tokResource, "alice"); err != nil {
		t.Fatal(err)
	}
	entry, err := a.h.BackupInstance("aiapp", root)
	if err != nil {
		t.Fatal(err)
	}
	// Changed after the backup: the archive's state comes back.
	if err := a.h.SetAIMode(context.Background(), "aiapp", "tok", "read_only", root); err != nil {
		t.Fatal(err)
	}
	if _, err := a.h.MintCredential(context.Background(), tokResource, "alice"); err != nil {
		t.Fatal(err)
	}

	// Each revoke_all checks the gate file at the moment it runs.
	var listedAtRevoke []bool
	a.engine.mu.Lock()
	gateRun := a.engine.execSplit
	a.engine.mu.Unlock()
	a.engine.setExecSplit(func(cid string, in docker.ExecInput) (*docker.ExecSplitResult, error) {
		if in.Cmd[0] == "/revoke" && strings.Contains(string(in.Stdin), "revoke_all") {
			b, _ := os.ReadFile(a.h.gatePath())
			f, _ := aigate.DecodeFile(b)
			listed := false
			if f != nil {
				listed = resourceByURL(f, tokResource) != nil
			}
			listedAtRevoke = append(listedAtRevoke, listed)
		}
		return gateRun(cid, in)
	})
	n := len(a.stdins("/revoke"))
	res, err := a.h.RestoreInstance("aiapp", entry.Archive, root)
	if err != nil {
		t.Fatal(err)
	}
	a.h.Wait()
	if got := a.stdins("/revoke")[n:]; len(got) == 0 || got[0] != `{"action":"revoke_all","prefix":"portcullis-ai-"}` {
		t.Errorf("revokes = %q", got)
	}
	if len(listedAtRevoke) == 0 || slices.Contains(listedAtRevoke, true) {
		t.Errorf("tok listed in the gate file while its revoke_all ran: %v", listedAtRevoke)
	}
	if s := a.companion("aiapp", "tok"); !s.Enabled || s.RevokePending || s.Mode != "read_write" {
		t.Errorf("tok = %+v, want the archive's state, revoke done", s)
	}
	if r := resourceByURL(a.gate(t), tokResource); r == nil || r.Mode != "read_write" {
		t.Errorf("gate = %v", urls(a.gate(t)))
	}
	if left := a.credsOf("aiapp", "tok"); len(left) != 0 {
		t.Errorf("entries after the restore = %+v", left)
	}
	if len(res.Warnings) != 0 {
		t.Errorf("warnings = %q", res.Warnings)
	}

	// The restored app's revoke_all fails: the entries are gone anyway
	// (deleted before the volumes are replaced), tok is switched off and
	// out of the gate file, the error is on the AI tab, in the op record
	// and in the warnings — the restore itself succeeds.
	if _, err := a.h.MintCredential(context.Background(), tokResource, "alice"); err != nil {
		t.Fatal(err)
	}
	a.failHook("/revoke", 1, "restored app down")
	res, err = a.h.RestoreInstance("aiapp", entry.Archive, root)
	if err != nil {
		t.Fatalf("restore = %v (AI never fails a restore)", err)
	}
	a.h.Wait()
	if left := a.credsOf("aiapp", "tok"); len(left) != 0 {
		t.Errorf("entries after the restore = %+v", left)
	}
	if s := a.companion("aiapp", "tok"); s.Enabled {
		t.Errorf("tok = %+v, want switched off", s)
	}
	if err := a.h.WritePolicy(); err != nil {
		t.Fatal(err)
	}
	if resourceByURL(a.gate(t), tokResource) != nil {
		t.Error("tok listed after a failed revoke_all")
	}
	if resourceByURL(a.gate(t), oldHdrURL) == nil {
		t.Error("hdr (no credentials, no revoke) not listed after the restore")
	}
	if _, ok := a.kc.scope(tokScope); ok {
		t.Error("tok's scope kept after it was switched off")
	}
	v, _ := a.h.InstanceAI("aiapp")
	for _, c := range v.Companions {
		if c.Name == "tok" && !strings.Contains(c.LastError, "restored app down") {
			t.Errorf("tok's LastError = %q", c.LastError)
		}
	}
	if op := a.h.LastOp("aiapp"); op == nil || op.Op != OpAI || op.OK || !strings.Contains(op.Error, "restored app down") {
		t.Errorf("op record = %+v", op)
	}
	if !slices.ContainsFunc(res.Warnings, func(w string) bool {
		return strings.Contains(w, "tok") && strings.Contains(w, "switched off") && strings.Contains(w, "restored app down")
	}) {
		t.Errorf("warnings = %q", res.Warnings)
	}
	if a.h.audit == nil || len(a.auditsOf("ai.disable", "aiapp/tok")) == 0 {
		t.Error("the switch-off isn't audited")
	}
}

// TestRestoreAIStateRefusals: the archive's AI state passes the switch-on
// refusals; a companion failing one is restored off with a warning, the
// restore goes on.
func TestRestoreAIStateRefusals(t *testing.T) {
	a := newLifecycleFixture(t)
	entry, err := a.h.BackupInstance("aiapp", root)
	if err != nil {
		t.Fatal(err)
	}
	rewriteArchiveMember(t, a, entry.Archive, aiMember, []byte(`{"companions":{"gone":{"enabled":true,"mode":"read_write"},"hdr":{"enabled":true,"mode":"read_only"},"tok":{"enabled":true,"mode":"bogus"}},"providers":["nope"]}`))
	res, err := a.h.RestoreInstance("aiapp", entry.Archive, root)
	if err != nil {
		t.Fatal(err)
	}
	a.h.Wait()
	ai := a.h.st.AIInstances["aiapp"]
	if _, ok := ai.Companions["gone"]; ok {
		t.Errorf("a companion the template doesn't declare was restored: %+v", ai)
	}
	if s := ai.Companions["tok"]; s.Enabled || s.Mode != "read_write" {
		t.Errorf("tok with a bad mode = %+v, want off with its default mode", s)
	}
	if s := ai.Companions["hdr"]; !s.Enabled {
		t.Errorf("hdr = %+v, want on", s)
	}
	if len(ai.Providers) != 0 {
		t.Errorf("providers = %v, want the unknown one dropped", ai.Providers)
	}
	for _, w := range []string{"gone", "bogus", "nope"} {
		if !slices.ContainsFunc(res.Warnings, func(s string) bool { return strings.Contains(s, w) }) {
			t.Errorf("no warning naming %s: %q", w, res.Warnings)
		}
	}

	// Over the cap (fix round 1): one warning, AI off, the restore goes on.
	var many strings.Builder
	many.WriteString(`{"companions":{`)
	for i := 0; i <= aiArchiveMax; i++ {
		if i > 0 {
			many.WriteString(",")
		}
		fmt.Fprintf(&many, `"c%d":{"enabled":true,"mode":"read_only"}`, i)
	}
	many.WriteString(`,"hdr":{"enabled":true,"mode":"read_only"}},"providers":[]}`)
	rewriteArchiveMember(t, a, entry.Archive, aiMember, []byte(many.String()))
	res, err = a.h.RestoreInstance("aiapp", entry.Archive, root)
	if err != nil {
		t.Fatalf("restore over the cap = %v", err)
	}
	if s := a.companion("aiapp", "hdr"); s.Enabled {
		t.Errorf("hdr over the cap = %+v", s)
	}
	n := 0
	for _, w := range res.Warnings {
		if strings.Contains(w, aiMember) {
			n++
		}
	}
	if n != 1 {
		t.Errorf("warnings over the cap = %q, want one naming %s", res.Warnings, aiMember)
	}
	if err := a.h.SetAISupport(context.Background(), "aiapp", "hdr", true, root); err != nil {
		t.Fatal(err)
	}

	// The master switch off: every companion restored off, warned.
	entry2, err := a.h.BackupInstance("aiapp", root)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.h.SetAISupport(context.Background(), "aiapp", "hdr", true, root); err != nil {
		t.Fatal(err)
	}
	a.h.mu.Lock()
	a.h.st.AI.Enabled = false
	a.h.mu.Unlock()
	res, err = a.h.RestoreInstance("aiapp", entry2.Archive, root)
	if err != nil {
		t.Fatal(err)
	}
	if s := a.companion("aiapp", "hdr"); s.Enabled {
		t.Errorf("hdr with the master switch off = %+v", s)
	}
	if !slices.ContainsFunc(res.Warnings, func(s string) bool { return strings.Contains(s, "hdr") && strings.Contains(s, "AI support is off") }) {
		t.Errorf("warnings = %q", res.Warnings)
	}
	a.h.mu.Lock()
	a.h.st.AI.Enabled = true
	// LoA 3 in the archive's policy (set behind the save path).
	a.h.st.AuthPolicies["aiapp"] = policy.AuthPolicy{Factors: []string{"mtls"}, Op: "any"}
	ai = a.h.st.AIInstances["aiapp"]
	ai.Companions = map[string]state.AICompanion{"hdr": {Enabled: true, Mode: "read_only"}}
	a.h.st.AIInstances["aiapp"] = ai
	a.h.mu.Unlock()
	entry3, err := a.h.BackupInstance("aiapp", root)
	if err != nil {
		t.Fatal(err)
	}
	res, err = a.h.RestoreInstance("aiapp", entry3.Archive, root)
	if err != nil {
		t.Fatal(err)
	}
	if s := a.companion("aiapp", "hdr"); s.Enabled {
		t.Errorf("hdr at LoA 3 = %+v", s)
	}
	if !slices.ContainsFunc(res.Warnings, func(s string) bool { return strings.Contains(s, "hdr") && strings.Contains(s, mtlsRefusal) }) {
		t.Errorf("warnings = %q", res.Warnings)
	}
}

// TestRestoreAsStartsAIOff: a restore into a new id keeps the archive's
// modes and providers, every companion off, no scope created.
func TestRestoreAsStartsAIOff(t *testing.T) {
	a := newLifecycleFixture(t)
	if err := a.h.SetAIMode(context.Background(), "aiapp", "tok", "read_only", root); err != nil {
		t.Fatal(err)
	}
	entry, err := a.h.BackupInstance("aiapp", root)
	if err != nil {
		t.Fatal(err)
	}
	ensures := func() []string {
		a.kc.mu.Lock()
		defer a.kc.mu.Unlock()
		var out []string
		for _, c := range a.kc.calls {
			if strings.Contains(c, "aiapp-c") {
				out = append(out, c)
			}
		}
		return out
	}
	if _, err := a.h.RestoreInstanceAs(entry.Archive, "aiapp-c", root); err != nil {
		t.Fatal(err)
	}
	a.h.Wait()
	ai, ok := a.h.st.AIInstances["aiapp-c"]
	if !ok {
		t.Fatal("no AI state for the restored copy")
	}
	if s := ai.Companions["tok"]; s.Enabled || s.Mode != "read_only" || s.RevokePending {
		t.Errorf("tok = %+v, want off, mode read_only", s)
	}
	if s := ai.Companions["hdr"]; s.Enabled || s.Mode != "read_only" {
		t.Errorf("hdr = %+v, want off", s)
	}
	a.people.addGroup("users_aiapp-c", "alice")
	a.enable(t, "aiapp-c")
	if got := ensures(); len(got) != 0 {
		t.Errorf("Keycloak calls for the copy = %q", got)
	}
	for _, r := range a.gate(t).Resources {
		if r.Instance == "aiapp-c" {
			t.Errorf("the copy is in the gate file: %+v", r.URL)
		}
	}
	// Switching it on runs revoke_all first (G34).
	n := len(a.stdins("/revoke"))
	if err := a.h.SetAISupport(context.Background(), "aiapp-c", "tok", true, root); err != nil {
		t.Fatal(err)
	}
	if got := a.stdins("/revoke")[n:]; len(got) == 0 || !strings.Contains(got[0], "revoke_all") {
		t.Errorf("switch-on revokes = %q", got)
	}
}

// TestDeleteRemovesAI: step 3 (project down) removes the instance's AI
// entries (audited, reason deleted), its oauth-seen records, orphans and
// AIInstances entry; step 4 deletes its mcp:* scopes (detached first).
func TestDeleteRemovesAI(t *testing.T) {
	a := newLifecycleFixture(t)
	if _, err := a.h.MintCredential(context.Background(), tokResource, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := a.h.oauthSeenUpdate(func(m map[string][]string) bool {
		m["aiapp/x"] = []string{"alice"}
		m["other/x"] = []string{"bob"}
		return true
	}); err != nil {
		t.Fatal(err)
	}
	a.h.recordOrphan(aiOrphanID{Instance: "aiapp", Companion: "tok", User: "alice", ID: "o1"})
	a.h.recordOrphan(aiOrphanID{Instance: "other", Companion: "x", User: "bob", ID: "o2"})
	a.kc.mu.Lock()
	a.kc.failDelete = map[string]error{tokScope: errors.New("keycloak down")}
	a.kc.mu.Unlock()

	_, err := a.h.DeleteInstance("aiapp", "aiapp", root)
	if err == nil || !strings.Contains(err.Error(), tokScope) {
		t.Fatalf("delete with a failing scope delete = %v", err)
	}
	// Step 3 is done although step 4 failed.
	if left := a.credsOf("aiapp", "tok"); len(left) != 0 {
		t.Errorf("entries = %+v", left)
	}
	if _, ok := a.h.st.AIInstances["aiapp"]; ok {
		t.Error("AIInstances[aiapp] kept")
	}
	seen, _ := a.h.oauthSeen()
	if _, ok := seen["aiapp/x"]; ok || len(seen["other/x"]) != 1 {
		t.Errorf("oauth-seen = %v", seen)
	}
	orph, _ := a.h.orphansUpdate(func(l []aiOrphanID) ([]aiOrphanID, bool) { return l, false })
	if len(orph) != 1 || orph[0].Instance != "other" {
		t.Errorf("orphans = %+v", orph)
	}
	for _, r := range a.gate(t).Resources {
		if r.Instance == "aiapp" {
			t.Errorf("gate still lists %s", r.URL)
		}
	}
	got := a.auditsOf("ai.credential.revoke", "aiapp/tok/alice")
	if len(got) != 1 || got[0].Actor != "root" || !strings.Contains(got[0].Detail, "reason deleted") || got[0].Result != "ok" {
		t.Errorf("audit = %+v", got)
	}
	if _, ok := a.kc.scope(hdrScope); ok {
		t.Error("hdr's scope kept")
	}
	// The project was down before the entries went (no hook ran: the
	// app's tokens go with its volumes).
	for _, c := range a.engine.SplitCalls() {
		if c.in.Cmd[0] == "/revoke" {
			t.Errorf("a revoke hook ran during the delete: %s", c.in.Stdin)
		}
	}

	// The retry with the template gone too (and the AI state gone with
	// step 3): every realm scope named mcp:aiapp.* goes by prefix — tok
	// and a leftover no template or state names —, another instance's
	// mcp:aiapp-b.* stays.
	if err := os.RemoveAll(filepath.Join(a.src, "aiapp")); err != nil {
		t.Fatal(err)
	}
	a.h.Discover()
	if a.h.Template("aiapp") != nil {
		t.Fatal("aiapp still resolves")
	}
	a.kc.mu.Lock()
	a.kc.failDelete = nil
	a.kc.scopes["mcp:aiapp.old"] = keycloak.MCPScope{Name: "mcp:aiapp.old"}
	a.kc.scopes["mcp:aiapp-b.tok"] = keycloak.MCPScope{Name: "mcp:aiapp-b.tok"}
	a.kc.mu.Unlock()
	if _, err := a.h.DeleteInstance("aiapp", "aiapp", root); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{tokScope, "mcp:aiapp.old"} {
		if _, ok := a.kc.scope(s); ok {
			t.Errorf("%s kept", s)
		}
	}
	if _, ok := a.kc.scope("mcp:aiapp-b.tok"); !ok {
		t.Error("another instance's scope was deleted")
	}
	for _, c := range []string{"portcullis-ai-claude", "portcullis-ai-claude-code", "portcullis-ai-generic"} {
		if o := a.kc.opt(c); slices.Contains(o, tokScope) || slices.Contains(o, hdrScope) {
			t.Errorf("%s still has %v", c, o)
		}
	}
	if got := a.auditsOf("ai.credential.revoke", "aiapp/tok/alice"); len(got) != 1 {
		t.Errorf("audits after the retry = %+v", got)
	}
}

// Fix round 1 (2, 3): a restore's scope drop that fails is owed and the
// next AI client pass deletes it; a companion owing a revoke_all (the
// restored instance isn't running) loses its scope too.
func TestRestoreScopeDropOwed(t *testing.T) {
	a := newLifecycleFixture(t)
	entry, err := a.h.BackupInstance("aiapp", root)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.h.Disable("aiapp"); err != nil {
		t.Fatal(err)
	}
	a.h.Wait()
	if err := a.h.syncAIScopes(context.Background()); err != nil {
		t.Fatal(err)
	}
	a.kc.mu.Lock()
	a.kc.scopes[tokScope] = keycloak.MCPScope{Name: tokScope, Audience: tokResource}
	a.kc.failDelete = map[string]error{tokScope: errors.New("keycloak down")}
	a.kc.mu.Unlock()
	if _, err := a.h.RestoreInstance("aiapp", entry.Archive, root); err != nil {
		t.Fatal(err)
	}
	if s := a.companion("aiapp", "tok"); !s.Enabled || !s.RevokePending {
		t.Fatalf("tok = %+v, want on with a revoke_all owed", s)
	}
	if _, ok := a.kc.scope(tokScope); !ok {
		t.Fatal("the fake deleted the scope it was told to fail")
	}
	a.h.aiKCMu.Lock()
	owed := a.h.aiOwedDrops[tokScope]
	a.h.aiKCMu.Unlock()
	if !owed {
		t.Fatal("the failed drop isn't owed")
	}
	a.kc.mu.Lock()
	a.kc.failDelete = nil
	a.kc.mu.Unlock()
	if _, err := a.h.syncAIClients(context.Background()); err != nil {
		t.Logf("pass: %v", err)
	}
	if _, ok := a.kc.scope(tokScope); ok {
		t.Error("the owed drop wasn't retried")
	}
	a.h.aiKCMu.Lock()
	left := len(a.h.aiOwedDrops)
	a.h.aiKCMu.Unlock()
	if left != 0 {
		t.Errorf("owed drops left: %d", left)
	}
}

// Fix round 1 (7): a corrupt oauth-seen.json stops the delete with an
// error naming the file and what the admin must do.
func TestDeleteCorruptOAuthSeen(t *testing.T) {
	a := newLifecycleFixture(t)
	p := filepath.Join(a.h.cfg.DataDir, "ai", oauthSeenName)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := a.h.DeleteInstance("aiapp", "aiapp", root)
	if err == nil || !strings.Contains(err.Error(), p) || !strings.Contains(err.Error(), "fix or remove") {
		t.Fatalf("delete = %v", err)
	}
	if b, _ := os.ReadFile(p); string(b) != "{not json" {
		t.Error("the corrupt file was replaced")
	}
}
