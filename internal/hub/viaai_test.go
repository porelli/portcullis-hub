package hub

import (
	"context"
	"testing"

	"github.com/portcullis/hub/internal/credentials"
	"github.com/portcullis/hub/internal/directory"
)

// aiActor is an admin acting through the MCP listener (Task 13).
var aiActor = directory.Actor{User: "root", Via: directory.ViaAI, Client: "portcullis-ai-claude-code"}

// entriesSince returns the entries a appended after the first n.
func entriesSince(a *fakeAudit, n int) []directory.AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]directory.AuditEntry(nil), a.entries[n:]...)
}

func auditLen(a *fakeAudit) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.entries)
}

// dirEntries returns the directory's audit entries with action.
func dirEntries(t *testing.T, dir *directory.Service, action string) []directory.AuditEntry {
	t.Helper()
	all, err := dir.Audit.Recent(1000)
	if err != nil {
		t.Fatal(err)
	}
	var out []directory.AuditEntry
	for _, e := range all {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}

// wantVia: at least one entry (each of wantActions present), every one
// attributed to root via ai with the client.
func wantVia(t *testing.T, what string, entries []directory.AuditEntry, wantActions ...string) {
	t.Helper()
	if len(entries) == 0 {
		t.Errorf("%s: no audit entry", what)
		return
	}
	seen := map[string]bool{}
	for _, e := range entries {
		seen[e.Action] = true
		if e.Actor != aiActor.User || e.Via != aiActor.Via || e.Client != aiActor.Client {
			t.Errorf("%s: entry %s %s: actor=%q via=%q client=%q, want root via ai %s", what, e.Action, e.Target, e.Actor, e.Via, e.Client, aiActor.Client)
		}
	}
	for _, a := range wantActions {
		if !seen[a] {
			t.Errorf("%s: no %s entry in %+v", what, a, entries)
		}
	}
}

// TestViaAIReachesHubAudit (Task 7b): a via-AI actor calling the Hub's
// mutations — instance enable (its groups created in Users & Groups),
// settings save, folder assign, doctor fix, group delete (the directory's
// and an instance delete's, with the Hub's purge) and an admin credential
// revoke — leaves only entries that say via ai and the client; stored
// actors (op records, revoked_by) stay the user.
func TestViaAIReachesHubAudit(t *testing.T) {
	ctx := context.Background()

	t.Run("enable, settings save, group delete", func(t *testing.T) {
		f, audit, _ := privFixture(t)
		dir, ll := hubDirectory(t, f)
		ll.AddGroup("office_milan", "alice")
		if err := f.h.CreateInstance("privapp", "privapp2", nil); err != nil {
			t.Fatal(err)
		}
		// Enable: the instance's missing groups are created as the actor.
		if _, err := f.h.EnableAs("privapp2", aiActor); err != nil {
			t.Fatal(err)
		}
		wantVia(t, "enable", dirEntries(t, dir, "group.create"), "group.create")

		// Settings save.
		n := auditLen(audit)
		if _, err := f.h.SaveSettings("privapp", SettingsUpdate{
			Person: map[string]PersonChange{"tier": {Default: raw("basic"), Rows: rows("office_milan", "pro", "users_privapp", "basic")}},
			Groups: map[string][]GroupValueInput{"libraries": rows("office_milan", []string{"/milan"})},
		}, aiActor); err != nil {
			t.Fatal(err)
		}
		wantVia(t, "settings save", entriesSince(audit, n), "settings.change")

		// A group deleted in Users & Groups by the AI: the directory's
		// entry and the Hub's purge of the rows naming it.
		c, err := dir.CallerAs(ctx, aiActor)
		if err != nil {
			t.Fatal(err)
		}
		n = auditLen(audit)
		if _, err := dir.DeleteGroup(ctx, c, "office_milan", "office_milan"); err != nil {
			t.Fatal(err)
		}
		wantVia(t, "group delete (purge)", entriesSince(audit, n), "settings.purge")
		wantVia(t, "group delete (directory)", dirEntries(t, dir, "group.delete"), "group.delete")

		// An instance delete deletes its groups as the actor.
		if _, err := f.h.DeleteInstance("privapp2", "privapp2", aiActor); err != nil {
			t.Fatal(err)
		}
		dels := dirEntries(t, dir, "group.delete")
		if len(dels) != 3 {
			t.Errorf("group.delete entries = %+v, want office_milan + privapp2's two", dels)
		}
		wantVia(t, "instance delete's group delete", dels)
	})

	t.Run("folder assign", func(t *testing.T) {
		f, _, audit := assignFixture(t)
		enable(t, f, "immich")
		req := AssignRequest{Uses: []FolderUse{{Instance: "immich", Key: "library"}}}
		plan, err := f.h.PreviewAssign(ctx, "media", req)
		if err != nil {
			t.Fatal(err)
		}
		n := auditLen(audit)
		// A widening assign from the AI needs the confirmation the tool
		// consumed (Task 20).
		confirmed := aiActor
		confirmed.Confirmation = "AAAA-BBBB-CCCC"
		if _, err := f.h.StartAssign("media", req, plan.Hash, confirmed); err != nil {
			t.Fatal(err)
		}
		rec := waitFolderOp(t, f, "media")
		if !rec.OK {
			t.Fatalf("assign = %+v", rec)
		}
		if rec.Actor != "root" {
			t.Errorf("op record actor = %q, want the user only", rec.Actor)
		}
		wantVia(t, "folder assign", entriesSince(audit, n), "folder.assign", "folder.apply", "settings.change")
	})

	t.Run("doctor fix", func(t *testing.T) {
		f, audit := rebindFixture(t)
		plan, err := f.h.PreviewFix(ctx, smbFP, map[string]string{"address": "192.168.1.10"})
		if err != nil {
			t.Fatal(err)
		}
		n := auditLen(audit)
		op, err := f.h.ApplyFix(ctx, smbFP, map[string]string{"address": "192.168.1.10"}, plan.Hash, aiActor)
		if err != nil {
			t.Fatal(err)
		}
		rec := waitInstanceOp(t, f, "samba", op.OpID)
		if !rec.OK {
			t.Fatalf("rebind = %+v", rec)
		}
		if rec.Actor != "root" {
			t.Errorf("op record actor = %q, want the user only", rec.Actor)
		}
		f.h.Wait()
		wantVia(t, "doctor fix", entriesSince(audit, n), "doctor.fix", "settings.change")
	})

	t.Run("credential revoke", func(t *testing.T) {
		c := credSvcFixture(t)
		cc := c.create(t, "alice")
		credentials.Zero(cc.Password)
		n := auditLen(c.audit)
		if err := c.f.h.AdminRevokeCredential(ctx, smbID, smbKey, "alice", aiActor); err != nil {
			t.Fatal(err)
		}
		settle(c.f)
		wantVia(t, "credential revoke", entriesSince(c.audit, n), "credential.revoke")
		if m, _ := credOf(c.f.h, smbID, "alice"); m.RevokedBy != "root" {
			t.Errorf("revoked_by = %q, want the user only", m.RevokedBy)
		}
	})
}
