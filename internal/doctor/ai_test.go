package doctor

import (
	"strings"
	"testing"
)

// Plan 4 Task 20: the AI checks (contract §14.5 "AI support (NEW)").

const pinTok = "sha256:" + "aa" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd"

// aiOn is a healthy switched-on companion of aiapp.
func aiOn() AIIn {
	return AIIn{Instance: "aiapp", Label: "AI App", Companion: "tok", CompanionLabel: "Tokens", On: true, Status: "running",
		Policy: "passkey", LoA: 2, ImagePinned: pinTok, ImageRunning: pinTok}
}

// aiLinkOK: the finding opens aiapp's AI tab (never a settings option).
func aiLinkOK(t *testing.T, f Finding) {
	t.Helper()
	if f.Class != FixLink || f.Link == nil || f.Link.Instance != "aiapp" || f.Link.Tab != "ai" || f.Link.Option != "" {
		t.Errorf("%s: link = %+v class %q, want the AI tab of aiapp", f.Kind, f.Link, f.Class)
	}
	if len(f.Instances) != 1 || f.Instances[0] != "aiapp" {
		t.Errorf("%s: instances = %v", f.Kind, f.Instances)
	}
}

func TestAIDoctorChecks(t *testing.T) {
	// Healthy: no AI finding of any kind.
	for _, k := range []string{KindAICompanionUnhealthy, KindAIPolicyNeedsMTLS, KindAICredentialsRevoking, KindAICompanionImageOld} {
		if got := of(t, k, &Inputs{AI: []AIIn{aiOn()}}); len(got) != 0 {
			t.Errorf("%s on a healthy companion: %+v", k, got)
		}
	}

	t.Run("unhealthy", func(t *testing.T) {
		for _, st := range []string{"exited", "missing", "unhealthy", "restarting"} {
			a := aiOn()
			a.Status = st
			got := of(t, KindAICompanionUnhealthy, &Inputs{AI: []AIIn{a}})
			if len(got) != 1 || got[0].Severity != Problem || !strings.Contains(got[0].Title, "Tokens") || !strings.Contains(got[0].Title, "AI App") {
				t.Fatalf("%s: %+v", st, got)
			}
			aiLinkOK(t, got[0])
		}
		// Off, or a status the Hub couldn't read: not judged.
		a := aiOn()
		a.Status, a.On = "exited", false
		b := aiOn()
		b.Status = ""
		if got := of(t, KindAICompanionUnhealthy, &Inputs{AI: []AIIn{a, b}}); len(got) != 0 {
			t.Errorf("off / unknown = %+v", got)
		}
	})

	t.Run("mtls", func(t *testing.T) {
		a := aiOn()
		a.LoA, a.Policy = 3, "client certificate and passkey"
		got := of(t, KindAIPolicyNeedsMTLS, &Inputs{AI: []AIIn{a}})
		if len(got) != 1 || got[0].Severity != Problem || !strings.Contains(got[0].Why, "client certificate") {
			t.Fatalf("LoA 3 = %+v", got)
		}
		aiLinkOK(t, got[0])
		a.On = false
		if got := of(t, KindAIPolicyNeedsMTLS, &Inputs{AI: []AIIn{a}}); len(got) != 0 {
			t.Errorf("AI off at LoA 3 = %+v", got)
		}
	})

	t.Run("revoking", func(t *testing.T) {
		a := aiOn()
		a.Revoking, a.Reason = 2, "revoke hook tok-revoke failed (exit 1)"
		got := of(t, KindAICredentialsRevoking, &Inputs{AI: []AIIn{a}})
		if len(got) != 1 || got[0].Severity != Warning || !strings.Contains(got[0].Title, "AI App") || !strings.Contains(got[0].Title, "2 ") ||
			!strings.Contains(got[0].Why, "exit 1") {
			t.Fatalf("revoking = %+v", got)
		}
		aiLinkOK(t, got[0])
		// A companion off (pruned by a template update, its hook gone)
		// still owes the revocation: the finding explains it by hand.
		lost := AIIn{Instance: "aiapp", Label: "AI App", Companion: "lost", Revoking: 1, Pruned: true, NoHook: true,
			Reason: "companion lost: the template no longer has its revoke hook"}
		got = of(t, KindAICredentialsRevoking, &Inputs{AI: []AIIn{lost}})
		if len(got) != 1 || got[0].Severity != Warning || got[0].Class != FixExplain || len(got[0].Steps) == 0 ||
			!strings.Contains(strings.Join(got[0].Steps, " "), "by hand") || !strings.Contains(got[0].Why, "no longer has") {
			t.Fatalf("lost hook = %+v", got)
		}
		// app_oauth unmatched leavers (T27): the reason lines and a Dismiss
		// per person.
		um := AIIn{Instance: "ha", Label: "Home", Companion: "homeassistant", Unmatched: []string{"erin"},
			Reason: "erin left ha before their Home Assistant account could be matched: …"}
		got = of(t, KindAICredentialsRevoking, &Inputs{AI: []AIIn{um}})
		if len(got) != 1 || !strings.Contains(got[0].Title, "need attention") || got[0].Why != um.Reason ||
			len(got[0].Dismiss) != 1 || got[0].Dismiss[0] != (Dismiss{Instance: "ha", Companion: "homeassistant", User: "erin"}) {
			t.Fatalf("unmatched = %+v", got)
		}
		// app_oauth leftovers: people recorded, no hook left.
		left := AIIn{Instance: "aiapp", Label: "AI App", Companion: "dropped", Recorded: 2, NoHook: true}
		got = of(t, KindAICredentialsRevoking, &Inputs{AI: []AIIn{left}})
		if len(got) != 1 || !strings.Contains(got[0].Title, "2 people") || !strings.Contains(got[0].Why, "own sign-in") || got[0].Class != FixExplain {
			t.Fatalf("app_oauth leftovers = %+v", got)
		}
		// The hook's absence is said once (fix round 1).
		if n := strings.Count(got[0].Why, "no longer has"); n != 1 {
			t.Errorf("app_oauth leftovers name the missing hook %d times: %s", n, got[0].Why)
		}
		// The oauth-seen record unreadable (no instance): explained.
		unread := AIIn{Companion: "oauth-seen.json", Reason: "reading oauth-seen.json: permission denied"}
		got = of(t, KindAICredentialsRevoking, &Inputs{AI: []AIIn{unread}})
		if len(got) != 1 || got[0].Link != nil || !strings.Contains(got[0].Why, "permission denied") {
			t.Fatalf("unreadable record = %+v", got)
		}
		// Distinct fingerprints per companion.
		if got := of(t, KindAICredentialsRevoking, &Inputs{AI: []AIIn{a, lost, left}}); len(got) != 3 || got[0].FP == got[1].FP || got[1].FP == got[2].FP {
			t.Errorf("three companions = %+v", got)
		}
	})

	t.Run("image", func(t *testing.T) {
		a := aiOn()
		a.ImageRunning = "sha256:" + strings.Repeat("b", 64)
		got := of(t, KindAICompanionImageOld, &Inputs{AI: []AIIn{a}})
		if len(got) != 1 || got[0].Severity != Warning || !strings.Contains(got[0].Why, a.ImageRunning[:19]) || !strings.Contains(got[0].Why, pinTok[:19]) {
			t.Fatalf("old image = %+v", got)
		}
		aiLinkOK(t, got[0])
		// No pin in the template, nothing running, or AI off: not judged.
		for _, b := range []AIIn{func() AIIn { b := a; b.ImagePinned = ""; return b }(), func() AIIn { b := a; b.ImageRunning = ""; return b }(),
			func() AIIn { b := a; b.On = false; return b }()} {
			if got := of(t, KindAICompanionImageOld, &Inputs{AI: []AIIn{b}}); len(got) != 0 {
				t.Errorf("%+v: %+v", b, got)
			}
		}
	})

	// Every kind is in the catalogue.
	for _, k := range []string{KindAICompanionUnhealthy, KindAIPolicyNeedsMTLS, KindAICredentialsRevoking, KindAICompanionImageOld} {
		found := false
		for _, x := range Kinds() {
			found = found || x == k
		}
		if !found {
			t.Errorf("kind %s not registered", k)
		}
	}
}
