package hub

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/state"
)

// TestDeleteBackup (user ruling 2026-11-26, contract §11.5 "Deleting a
// backup"): the typed name confirms, the archive and its emptied
// directory go, the list no longer shows it, and every call is audited
// instance.backup_delete (refusals as refused).
func TestDeleteBackup(t *testing.T) {
	f, audit, _ := grafanaB(t)
	entry, err := f.h.BackupInstance("grafana-b", directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.h.DeleteBackup(entry.Archive, "grafana-b", directory.Human("root")); statusOf(err) != 400 {
		t.Errorf("wrong confirm = %v", err)
	}
	if a := audit.lastOf("instance.backup_delete"); a.Result != "refused" || a.Target != "grafana-b" || a.Detail != "archive="+entry.Archive {
		t.Errorf("audit of a refusal = %+v", a)
	}
	if _, err := os.Stat(archivePath(f, entry.Archive)); err != nil {
		t.Fatalf("a refused delete removed the archive: %v", err)
	}
	if err := f.h.DeleteBackup(entry.Archive, entry.Archive, directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(archivePath(f, entry.Archive)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("archive still there: %v", err)
	}
	if _, err := os.Stat(filepath.Join(f.data, "backups", "grafana-b")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("empty instance directory kept: %v", err)
	}
	if l, _ := f.h.ListBackups(""); len(l) != 0 {
		t.Errorf("still listed: %+v", l)
	}
	if a := audit.lastOf("instance.backup_delete"); a.Result != "ok" || a.Actor != "root" || a.Target != "grafana-b" || a.Detail != "archive="+entry.Archive {
		t.Errorf("audit = %+v", a)
	}
	// Gone now: 404.
	if err := f.h.DeleteBackup(entry.Archive, entry.Archive, directory.Human("root")); statusOf(err) != 404 {
		t.Errorf("second delete = %v", err)
	}
}

// TestDeleteBackupStrictNames: no path is built from anything but an
// archive name (traversal, absolute, other files: 400), and only what
// ListBackups lists is removable: a symlink or a foreign manifest at an
// archive name is 404 and stays (so does what it points at).
func TestDeleteBackupStrictNames(t *testing.T) {
	f, _, _ := grafanaB(t)
	entry, err := f.h.BackupInstance("grafana-b", directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "../state.yaml", "grafana-b/../../state.yaml", "/etc/passwd", "grafana-b/20261126T025030Z.tar/..",
		"grafana-b/x.tar", "grafana-b\\20261126T025030Z.tar", "Grafana-B/20261126T025030Z.tar", "grafana-b/20261126T025030Z.tar.partial", "state.yaml"} {
		if err := f.h.DeleteBackup(bad, bad, directory.Human("root")); statusOf(err) != 400 {
			t.Errorf("DeleteBackup(%q) = %v, want 400", bad, err)
		}
	}
	// A symlink at an archive name, pointing at the real archive.
	link := "grafana-b/20990101T000000Z.tar"
	if err := os.Symlink(archivePath(f, entry.Archive), archivePath(f, link)); err != nil {
		t.Fatal(err)
	}
	if err := f.h.DeleteBackup(link, link, directory.Human("root")); statusOf(err) != 404 {
		t.Errorf("symlink = %v, want 404", err)
	}
	// Another instance's archive copied under this instance's directory.
	foreign := "grafana-c/20990101T000000Z.tar"
	os.MkdirAll(filepath.Dir(archivePath(f, foreign)), 0700)
	b, _ := os.ReadFile(archivePath(f, entry.Archive))
	writeFile(t, archivePath(f, foreign), string(b))
	if err := f.h.DeleteBackup(foreign, foreign, directory.Human("root")); statusOf(err) != 404 {
		t.Errorf("foreign manifest = %v, want 404", err)
	}
	for _, p := range []string{archivePath(f, entry.Archive), archivePath(f, foreign)} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s removed: %v", p, err)
		}
	}
	if _, err := os.Lstat(archivePath(f, link)); err != nil {
		t.Errorf("symlink removed: %v", err)
	}
}

// TestDeleteBackupRefusedWhileRestoring: an archive a running restore
// uses is 409 until the restore ends; the pre-restore backup the
// restore took is too (a rollback needs it) while the instance is
// "restoring". Afterwards both can go.
func TestDeleteBackupRefusedWhileRestoring(t *testing.T) {
	f, _, _ := grafanaB(t)
	entry, err := f.h.BackupInstance("grafana-b", directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	reached, release := blockStep(t, f.h, StepVolumes)
	a, err := f.h.StartRestore("grafana-b", entry.Archive, directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	<-reached
	if err := f.h.DeleteBackup(entry.Archive, entry.Archive, directory.Human("root")); statusOf(err) != 409 || !strings.Contains(err.Error(), "busy") {
		t.Errorf("delete during the restore = %v, want 409 busy", err)
	}
	var pre string
	for _, b := range mustList(t, f) {
		if b.Reason == BackupRestore {
			pre = b.Archive
		}
	}
	if pre == "" {
		t.Fatal("no pre-restore backup")
	}
	if err := f.h.DeleteBackup(pre, pre, directory.Human("root")); statusOf(err) != 409 || !strings.Contains(err.Error(), "busy") {
		t.Errorf("delete of the pre-restore backup during the restore = %v, want 409", err)
	}
	close(release)
	if r := waitOp(t, f.h, "grafana-b", a.OpID); !r.OK {
		t.Fatalf("restore = %+v", r)
	}
	for _, x := range []string{entry.Archive, pre} {
		if err := f.h.DeleteBackup(x, x, directory.Human("root")); err != nil {
			t.Errorf("delete of %s after the restore = %v", x, err)
		}
	}
}

// TestDeleteBackupRefusedForUnfinishedDelete: the backup of a delete that
// stopped part-way ("deleting") is the instance's only copy: 409.
func TestDeleteBackupRefusedForUnfinishedDelete(t *testing.T) {
	f, _, groups := grafanaB(t)
	groups.delErr = errors.New("lldap down")
	if _, err := f.h.DeleteInstance("grafana-b", "grafana-b", directory.Human("root")); err == nil {
		t.Fatal("delete did not fail")
	}
	l := mustList(t, f)
	if len(l) != 1 {
		t.Fatalf("backups = %+v", l)
	}
	if err := f.h.DeleteBackup(l[0].Archive, l[0].Archive, directory.Human("root")); statusOf(err) != 409 || !strings.Contains(err.Error(), "unfinished delete") {
		t.Errorf("delete = %v, want 409", err)
	}
	// Once the delete finished, it's an ordinary archive of a deleted
	// instance.
	groups.delErr = nil
	if _, err := f.h.DeleteInstance("grafana-b", "grafana-b", directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	if err := f.h.DeleteBackup(l[0].Archive, l[0].Archive, directory.Human("root")); err != nil {
		t.Errorf("delete after the instance's delete = %v", err)
	}
}

func mustList(t *testing.T, f *fixture) []BackupEntry {
	t.Helper()
	l, err := f.h.ListBackups("")
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// TestDeleteBackupRefusedWhileRestoringAs: the source archive of a
// restore into a new instance is leased (the op record is the new id's,
// not the archive's instance): 409 until the restore ends.
func TestDeleteBackupRefusedWhileRestoringAs(t *testing.T) {
	f, _, _ := grafanaB(t)
	entry, err := f.h.BackupInstance("grafana-b", directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	reached, release := blockStep(t, f.h, StepVolumes)
	a, err := f.h.StartRestoreAs(entry.Archive, "grafana-x", directory.Human("root"), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	<-reached
	if err := f.h.DeleteBackup(entry.Archive, entry.Archive, directory.Human("root")); statusOf(err) != 409 || !strings.Contains(err.Error(), "a restore from") {
		t.Errorf("delete during the restore = %v, want 409", err)
	}
	close(release)
	if r := waitOp(t, f.h, "grafana-x", a.OpID); !r.OK {
		t.Fatalf("restore = %+v", r)
	}
	if err := f.h.DeleteBackup(entry.Archive, entry.Archive, directory.Human("root")); err != nil {
		t.Errorf("delete after the restore = %v", err)
	}
}

// TestDeleteBackupRacesDelete (review I3): between a delete writing its
// backup and recording it in state ("deleting", e.Backup), the archive is
// listed but nothing in state names it yet. DeleteBackup takes the
// instance's app lock, so it is refused 409 (busy) there and the delete
// finishes with its archive in place.
func TestDeleteBackupRacesDelete(t *testing.T) {
	f, _, _ := grafanaB(t)
	var archive string
	var refused error
	f.h.testHookDeleteBackedUp = func(id string) {
		l, _ := f.h.ListBackups(id)
		if len(l) != 1 {
			t.Errorf("backups at the hook = %+v", l)
			return
		}
		archive = l[0].Archive
		refused = f.h.DeleteBackup(archive, archive, directory.Human("root"))
	}
	res, err := f.h.DeleteInstance("grafana-b", "grafana-b", directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	if statusOf(refused) != 409 || !strings.Contains(refused.Error(), "busy") {
		t.Errorf("DeleteBackup in the window = %v, want 409 busy", refused)
	}
	if res.Backup != archive {
		t.Errorf("result backup %q, archive %q", res.Backup, archive)
	}
	if _, err := os.Stat(archivePath(f, archive)); err != nil {
		t.Errorf("the delete's archive is gone: %v", err)
	}
}

// TestDeleteBackupRefusedWhenNeeded (review M3): an archive state still
// names is 409 even with no operation running — an interrupted restore's
// pre-restore backup, a restore into a new id's source, a move's archive
// — and so is the one a pending core restore names.
func TestDeleteBackupRefusedWhenNeeded(t *testing.T) {
	f, _, _ := grafanaB(t)
	entry, err := f.h.BackupInstance("grafana-b", directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	a := entry.Archive
	set := func(fn func(e *state.Instance)) {
		f.h.mu.Lock()
		e := f.h.st.Instances["grafana-b"]
		fn(&e)
		f.h.st.Instances["grafana-b"] = e
		f.h.mu.Unlock()
	}
	for _, c := range []struct {
		name string
		fn   func(e *state.Instance)
		want string
	}{
		{"interrupted restore", func(e *state.Instance) { e.State, e.Backup = state.InstanceRestoring, a }, "rollback"},
		{"restore into a new id", func(e *state.Instance) { e.State, e.Backup, e.RestoreAs = state.InstanceRestoring, "", a }, "unfinished restore into"},
		{"move", func(e *state.Instance) {
			e.State, e.RestoreAs, e.Move = state.InstanceMoving, "", &state.Move{Archive: a}
		}, "move of"},
	} {
		saved := f.h.st.Instances["grafana-b"]
		set(c.fn)
		if err := f.h.DeleteBackup(a, a, directory.Human("root")); statusOf(err) != 409 || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want 409 %q", c.name, err, c.want)
		}
		set(func(e *state.Instance) { *e = saved })
	}
	if _, err := os.Stat(archivePath(f, a)); err != nil {
		t.Fatalf("archive removed: %v", err)
	}
	if err := f.h.DeleteBackup(a, a, directory.Human("root")); err != nil {
		t.Errorf("delete once nothing needs it = %v", err)
	}
}
