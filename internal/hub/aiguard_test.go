package hub

import (
	"context"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/doctor"
	"github.com/portcullis/hub/internal/folderfix"
)

// Task 20 fix round 1: the Hub's own refusal (aiUnconfirmed) of the
// operations the Portcullis MCP may run only with a consumed
// confirmation. Each row sets up an operation that would run for a
// human (or a confirmed AI call), then asks for it as the AI without a
// confirmation: 409 naming the confirmation, and nothing changed. With
// the guard removed every row fails (the operation runs).

var unconfirmedAI = directory.Actor{User: "root", Via: directory.ViaAI, Client: "portcullis-ai-claude"}

// refusedUnconfirmed checks a guard refusal: 409, "confirmation" in the
// text, the state dump unchanged.
func refusedUnconfirmed(t *testing.T, f *fixture, before string, err error) {
	t.Helper()
	if statusOf(err) != 409 || !strings.Contains(err.Error(), "confirmation") {
		t.Errorf("AI without a confirmation = %v, want 409 asking for one", err)
	}
	if stateDump(t, f) != before {
		t.Error("the refused operation changed the state")
	}
}

// appliedMedia is assignFixture with media applied to immich (a last
// apply with its snapshot: undo is offered).
func appliedMedia(t *testing.T) (*fixture, *assignDisk) {
	t.Helper()
	f, d, _ := assignFixture(t)
	f.h.SetPeople(newFakePeople("erin"))
	enable(t, f, "immich")
	if _, rec := assign(t, f, "media", libraryReq); !rec.OK {
		t.Fatal(rec)
	}
	return f, d
}

func TestHubRefusesUnconfirmedAI(t *testing.T) {
	ctx := context.Background()

	t.Run("StartUndo", func(t *testing.T) {
		f, d := appliedMedia(t)
		d.restore = folderfix.Report{Changed: 10}
		p, err := f.h.PreviewUndo(ctx, "media")
		if err != nil {
			t.Fatal(err)
		}
		before, last := stateDump(t, f), f.h.LastOp(opKeyFolder("media")).OpID
		_, err = f.h.StartUndo("media", p.Hash, unconfirmedAI)
		refusedUnconfirmed(t, f, before, err)
		if r := f.h.LastOp(opKeyFolder("media")); r.OpID != last {
			t.Errorf("an undo ran: %+v", r)
		}
	})

	t.Run("DeleteFolder", func(t *testing.T) {
		f, _, _ := assignFixture(t)
		before := stateDump(t, f)
		refusedUnconfirmed(t, f, before, f.h.DeleteFolder("media", unconfirmedAI))
		if _, ok := storedFolder(f, "media"); !ok {
			t.Error("media deleted")
		}
	})

	t.Run("ApplyRecheck different directory", func(t *testing.T) {
		f, d := appliedMedia(t)
		d.mu.Lock()
		d.paths["/srv/media"].ino = 777
		d.mu.Unlock()
		chk, err := f.h.PreviewRecheck(ctx, "media")
		if err != nil || !chk.DifferentDirectory {
			t.Fatalf("preview = %+v %v", chk, err)
		}
		before := stateDump(t, f)
		_, err = f.h.ApplyRecheck(ctx, "media", chk.Hash, true, unconfirmedAI)
		refusedUnconfirmed(t, f, before, err)
		if fo, _ := storedFolder(f, "media"); fo.Ino == 777 {
			t.Error("the other directory was stored")
		}
	})

	t.Run("ApplyFix undo_folder", func(t *testing.T) {
		f, d := appliedMedia(t)
		fo, _ := storedFolder(f, "media")
		f.h.storeScan("media", &folderfix.Report{Version: 1, Mode: "scan", FSType: "ext4", ACL: true, Entries: 10, Dev: fo.Dev, Ino: fo.Ino,
			Expected: &folderfix.Conformance{Group: folderfix.Count{N: 4}}}, nil)
		d.restore = folderfix.Report{Changed: 10}
		fp := doctor.Fingerprint(doctor.KindFolderOwner, "folder:media")
		params := map[string]string{"fix": doctor.FixUndoFolder}
		p, err := f.h.PreviewFix(ctx, fp, params)
		if err != nil {
			t.Fatal(err)
		}
		before := stateDump(t, f)
		_, err = f.h.ApplyFix(ctx, fp, params, p.Hash, unconfirmedAI)
		refusedUnconfirmed(t, f, before, err)
	})

	t.Run("ApplyFix revoke_leaver", func(t *testing.T) {
		c := credSvcFixture(t)
		f := c.f
		c.create(t, "bob")
		c.people.removeMember("users_"+smbID, "bob")
		got := findingsOf(t, f, doctor.KindCredentialWithoutAccess)
		if len(got) != 1 {
			t.Fatalf("canary = %+v", got)
		}
		p, err := f.h.PreviewFix(ctx, got[0].FP, nil)
		if err != nil {
			t.Fatal(err)
		}
		before := stateDump(t, f)
		_, err = f.h.ApplyFix(ctx, got[0].FP, nil, p.Hash, unconfirmedAI)
		refusedUnconfirmed(t, f, before, err)
		if m, _ := credOf(f.h, smbID, "bob"); m.RevokedBy != "" {
			t.Errorf("bob's credential revoked by %q", m.RevokedBy)
		}
	})

	t.Run("ApplyFix person_tree_owner", func(t *testing.T) {
		e := treeFixture(t)
		f := e.f
		e.scan(t)
		fp := doctor.TreeFP(doctor.KindPersonTreeOwner, smbID, "homes", "alice")
		p, err := f.h.PreviewFix(ctx, fp, nil)
		if err != nil {
			t.Fatal(err)
		}
		before := stateDump(t, f)
		_, err = f.h.ApplyFix(ctx, fp, nil, p.Hash, unconfirmedAI)
		refusedUnconfirmed(t, f, before, err)
	})
}
