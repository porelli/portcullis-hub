package httpapi

import (
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/directory"
)

// TestMySignInToolClasses (D33): my_sign_in R (the view and the last 20
// history entries), the two handoffs R carrying only the Sign-in page's
// link, revoke_my_certificate W, audited cert.revoke via ai; none takes
// a person.
func TestMySignInToolClasses(t *testing.T) {
	e, ca := signInEnv(t)
	byName := map[string]Tool{}
	for _, tl := range e.s.tools(ScopePeople) {
		byName[tl.Name] = tl
	}
	for n, want := range map[string]struct {
		class ToolClass
		twin  string
	}{
		"my_sign_in":             {ClassRead, "GET /api/me/signin"},
		"my_browser_certificate": {ClassRead, "POST /api/me/signin/browser-certificates"},
		"my_password":            {ClassRead, "PUT /api/me/signin/password"},
		"revoke_my_certificate":  {ClassWrite, "DELETE /api/me/signin/certificates/{serial}"},
	} {
		tl, ok := byName[n]
		if !ok || tl.Class != want.class || tl.Twin != want.twin || tl.Perm != "" {
			t.Errorf("%s = %+v", n, tl)
		}
	}
	if byName["revoke_my_certificate"].Audit != "cert.revoke" {
		t.Error("revoke_my_certificate has no audit action")
	}
	txt, isErr := e.people(t, "alice", "my_sign_in", map[string]any{})
	if isErr || !strings.Contains(txt, `"sign_in"`) || !strings.Contains(txt, `"history"`) || !strings.Contains(txt, "0a:02") || strings.Contains(txt, "0b:01") {
		t.Errorf("my_sign_in = %s", txt)
	}
	for _, n := range []string{"my_browser_certificate", "my_password"} {
		txt, isErr := e.people(t, "alice", n, map[string]any{})
		if isErr || !strings.Contains(txt, "https://people.example.org/signin") || strings.Contains(txt, routeP12Password) || strings.Contains(txt, "p12\"") {
			t.Errorf("%s = %s", n, txt)
		}
	}
	if len(ca.revokes) != 0 {
		t.Fatal("a read revoked")
	}
	// Another person's serial: 404; the caller's own: revoked via ai.
	if txt, isErr := e.people(t, "alice", "revoke_my_certificate", map[string]any{"serial": "0b:01"}); !isErr || !strings.HasPrefix(txt, "404: ") {
		t.Errorf("bob's serial = %q %v", txt, isErr)
	}
	if txt, isErr := e.people(t, "alice", "revoke_my_certificate", map[string]any{"serial": "0a:02"}); isErr {
		t.Errorf("own = %q", txt)
	}
	if a := lastEntry(t, e, "cert.revoke"); a.Actor != "alice" || a.Via != directory.ViaAI || a.Client != mcpClient || a.Result != "ok" {
		t.Errorf("audit = %+v", a)
	}
	// No person argument: an injected user is refused, nothing runs.
	if _, isErr := e.people(t, "alice", "revoke_my_certificate", map[string]any{"serial": "0a:02", "user": "bob"}); !isErr {
		t.Error("an injected user was accepted")
	}
	if len(ca.revokes) != 1 {
		t.Errorf("revokes %v", ca.revokes)
	}
}
