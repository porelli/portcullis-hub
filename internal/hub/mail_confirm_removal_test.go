package hub

import (
	"context"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/doctor"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/state"
)

// confirmIn is a full confirmation of uuids: the pending removal's
// phrase and a fresh security-key proof (the Hub listener verifies it).
func confirmIn(h *Hub, uuids []string) ConfirmRemovalInput {
	h.SetFreshAuth(ListenerHub, &touchFA{method: "security_key"})
	h.freshAuthReady.Store(true)
	h.mu.Lock()
	if h.st.SignIn.Methods == nil {
		h.st.SignIn.Methods = map[string]bool{}
	}
	for k := range allOn() {
		h.st.SignIn.Methods[string(k)] = true
	}
	n := 0
	if p := h.st.Mail.PendingRemoval; p != nil {
		n = len(p.Accounts)
	}
	h.mu.Unlock()
	return ConfirmRemovalInput{Accounts: uuids, Confirm: mailRemovalPhrase(n), Proof: &freshauth.Proof{Code: "c", CodeVerifier: "v", Nonce: "n"}}
}

// TestConfirmRemovalNeedsProofAndPhrase (Ruling R-CONFIRM-REMOVAL): a
// non-admin 403; AI / MCP 403; no proof 403; a missing or wrong phrase
// 400 naming it (no proof spent); a stale proof 403; the full one
// confirms; audited with the list; the phrase is in the settings view.
func TestConfirmRemovalNeedsProofAndPhrase(t *testing.T) {
	w := wiredFix(t)
	const a, b = "0b0b0b0b-0000-4000-8000-0000000000a1", "0b0b0b0b-0000-4000-8000-0000000000a2"
	w.h.mu.Lock()
	w.h.st.Mail.PendingRemoval = &state.MailPendingRemoval{Since: w.now, Accounts: []state.MailPendingAccount{{Username: "x", UUID: a}, {Username: "y", UUID: b}}}
	w.h.mu.Unlock()
	ctx := context.Background()
	full := confirmIn(w.h, []string{a, b})
	if full.Confirm != "remove 2 mailboxes" {
		t.Fatalf("phrase %q", full.Confirm)
	}
	if v := w.h.MailSettingsView(); v.PendingRemoval == nil || v.PendingRemoval.ConfirmPhrase != "remove 2 mailboxes" {
		t.Fatalf("view %+v", v.PendingRemoval)
	}
	if err := w.h.ConfirmMailRemoval(ctx, full, directory.Human("alice")); statusOf(err) != 403 {
		t.Fatalf("non-admin: %v", err)
	}
	ai := directory.Human("root")
	ai.Via = "mcp"
	if err := w.h.ConfirmMailRemoval(ctx, full, ai); statusOf(err) != 403 {
		t.Fatalf("MCP: %v", err)
	}
	noProof := full
	noProof.Proof = nil
	if err := w.h.ConfirmMailRemoval(ctx, noProof, directory.Human("root")); statusOf(err) != 403 {
		t.Fatalf("no proof: %v", err)
	}
	fa := &touchFA{method: "security_key"}
	w.h.SetFreshAuth(ListenerHub, fa)
	for _, phrase := range []string{"", "remove 3 mailboxes", "yes"} {
		in := full
		in.Confirm = phrase
		if err := w.h.ConfirmMailRemoval(ctx, in, directory.Human("root")); statusOf(err) != 400 || !strings.Contains(err.Error(), `type "remove 2 mailboxes" to confirm`) {
			t.Fatalf("phrase %q: %v", phrase, err)
		}
	}
	if fa.calls.Load() != 0 {
		t.Fatal("a wrong phrase spent the proof")
	}
	fa.mu.Lock()
	fa.err = &freshauth.Error{Reason: "stale"}
	fa.mu.Unlock()
	if err := w.h.ConfirmMailRemoval(ctx, full, directory.Human("root")); statusOf(err) != 403 {
		t.Fatalf("stale proof: %v", err)
	}
	fa.mu.Lock()
	fa.err = nil
	fa.mu.Unlock()
	if err := w.h.ConfirmMailRemoval(ctx, full, directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	if v := w.h.MailSettingsView(); v.PendingRemoval == nil || !v.PendingRemoval.Confirmed {
		t.Fatalf("not confirmed: %+v", v.PendingRemoval)
	}
	if e := w.audit.last(); e.Action != "mail.confirm_removal" || !strings.Contains(e.Detail, a) || !strings.Contains(e.Detail, b) || e.Result != "ok" {
		t.Fatalf("audit %+v", e)
	}
}

// TestConfirmRemovalDoctorFixPointsToSettings (R-CONFIRM-REMOVAL): the
// doctor fix never confirms (no proof, no phrase): it names where.
func TestConfirmRemovalDoctorFixPointsToSettings(t *testing.T) {
	w := wiredFix(t)
	const a = "0b0b0b0b-0000-4000-8000-0000000000b1"
	w.h.mu.Lock()
	w.h.st.Mail.PendingRemoval = &state.MailPendingRemoval{Since: w.now, Accounts: []state.MailPendingAccount{{Username: "x", UUID: a}}}
	w.h.mu.Unlock()
	fx := mailConfirmRemovalFixer{}
	plan, err := fx.Preview(context.Background(), w.h, doctor.Finding{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fx.Apply(w.h, doctor.Finding{}, nil, plan.Hash, directory.Human("root")); statusOf(err) != 409 || err.Error() != MailConfirmRemovalElsewhereText {
		t.Fatalf("apply: %v", err)
	}
	if v := w.h.MailSettingsView(); v.PendingRemoval == nil || v.PendingRemoval.Confirmed {
		t.Fatal("the doctor fix confirmed")
	}
}
