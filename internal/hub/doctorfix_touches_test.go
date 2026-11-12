package hub

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/doctor"
)

// Plan 4 Task 20 (G45, contract §14.6 NEW): FixPlan.TouchesData — true for
// the fixes that change data on disk, ownership, ACLs or credentials —
// and ApplyFix's refusal of such a fix from the AI without a
// confirmation.

// fixerTouchesData is the audit of every registered fixer (a new fixer
// fails the test until it is added here).
var fixerTouchesData = map[string]bool{
	doctor.FixManageAsFolder:  true,  // defines a folder and applies it: group, setgid, ACLs on every entry
	doctor.FixReapplyFolder:   true,  // the folder assignment: group, mode and ACLs on disk
	doctor.FixUndoFolder:      true,  // restores the snapshot: group, owner, mode and ACLs on disk
	doctor.FixRebindPort:      false, // a <KEY>_BIND setting and a restart: no data, ownership or credential
	doctor.FixRevokeLeaver:    true,  // revokes a file-share credential
	doctor.FixPersonTreeOwner: true,  // chown + chmod of a person's folder
	doctor.FixDNSApply:        false, // DNS records at the provider: no data on disk, no access (F9)
	doctor.FixDNSSECSign:      false, // zone signing at the provider: no data on disk, no access (but AlwaysConfirm)
}

func TestFixersDeclareTouchesData(t *testing.T) {
	fixersMu.RLock()
	kinds := make([]string, 0, len(fixers))
	for k := range fixers {
		kinds = append(kinds, k)
	}
	fixersMu.RUnlock()
	slices.Sort(kinds)
	for _, k := range kinds {
		want, audited := fixerTouchesData[k]
		if !audited {
			t.Errorf("fixer %s isn't in the TouchesData audit", k)
			continue
		}
		if got := fixerFor(k).TouchesData(); got != want {
			t.Errorf("fixer %s: TouchesData %v, want %v", k, got, want)
		}
	}
	if len(kinds) != len(fixerTouchesData) {
		t.Errorf("fixers %v, audit %d entries", kinds, len(fixerTouchesData))
	}
}

func TestFixPlanTouchesData(t *testing.T) {
	ctx := context.Background()
	// rebind_port: config only.
	f, _ := rebindFixture(t)
	p, err := f.h.PreviewFix(ctx, smbFP, map[string]string{"address": "192.168.1.10"})
	if err != nil || p.TouchesData {
		t.Fatalf("rebind plan = %+v %v, want touches_data false", p, err)
	}
	if b := mustJSON(t, p); !strings.Contains(b, `"touches_data":false`) {
		t.Errorf("plan JSON = %s", b)
	}
	// manage_as_folder: data.
	m, _, _ := manageFixture(t)
	p, err = m.h.PreviewFix(ctx, mediaFP, nil)
	if err != nil || !p.TouchesData {
		t.Fatalf("manage plan = %+v %v, want touches_data true", p, err)
	}
	// From the AI without a confirmation, a data fix is refused before
	// anything runs (defence in depth: the tool asks for one first); the
	// config-only fix isn't.
	ai := directory.Actor{User: "admin", Via: directory.ViaAI, Client: "portcullis-ai-claude"}
	before := stateDump(t, m)
	if _, err := m.h.ApplyFix(ctx, mediaFP, nil, p.Hash, ai); statusOf(err) != 409 || !strings.Contains(err.Error(), "confirmation") {
		t.Errorf("AI apply without confirmation = %v, want 409", err)
	}
	if stateDump(t, m) != before {
		t.Error("the refused fix changed something")
	}
	rp, _ := f.h.PreviewFix(ctx, smbFP, map[string]string{"address": "192.168.1.10"})
	if op, err := f.h.ApplyFix(ctx, smbFP, map[string]string{"address": "192.168.1.10"}, rp.Hash, ai); err != nil || op == nil {
		t.Errorf("AI rebind = %v %v", op, err)
	}
	waitIdle(t, f, "samba")
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
