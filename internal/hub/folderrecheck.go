package hub

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"golang.org/x/text/language"
	"golang.org/x/text/message"

	"github.com/portcullis/hub/internal/doctor"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/folderfix"
)

// Re-check identity (H2, contract §14.1): a folder's root is stored as
// its device, inode and mount root, and every run checks them. A btrfs
// subvolume's device number (an anonymous device assigned at mount) and
// LVM / dm minors can change across a reboot: the folder is the same
// directory, yet every up, apply, undo and scan refuses it. The re-check
// probes and scans the folder's path again, previews the stored and the
// current identity, and stores the current one once the admin confirms.

// FolderIdentity is what identifies a folder's root on the host.
type FolderIdentity struct {
	Dev       uint64 `json:"dev"`
	Ino       uint64 `json:"ino"`
	MountRoot string `json:"mount_root"`
}

// IdentityCheck is a re-check's preview.
type IdentityCheck struct {
	Folder  string         `json:"folder"`
	Path    string         `json:"path"`
	Old     FolderIdentity `json:"old"`
	New     FolderIdentity `json:"new"`
	Changed bool           `json:"changed"`
	// DifferentDirectory: the inode changed — another directory, not a
	// reboot: storing it needs confirm_different_directory and clears
	// the last apply (follow-up (b)).
	DifferentDirectory bool     `json:"different_directory"`
	FSType             string   `json:"fs_type"`
	Files              int64    `json:"files"`
	Dirs               int64    `json:"dirs"`
	Partial            bool     `json:"partial"`
	Lines              []string `json:"lines"`
	// Hash binds the apply to this preview (the folder, its path, both
	// identities and its users).
	Hash string `json:"plan_hash"`
}

// differentDirectory: a root whose stored and current identity differ is
// another directory — not a reboot — when its inode changed, or when its
// device AND its mount root changed: a filesystem or subvolume root keeps
// its inode (btrfs 256, ext4 2), so a matching inode proves nothing there.
// A btrfs reboot changes the device only (last round 1). An unknown
// current mount root ("") counts as changed (fail closed).
func differentDirectory(storedDev, storedIno uint64, storedMR string, dev, ino uint64, mr string) bool {
	return ino != storedIno || (dev != storedDev && mr != storedMR)
}

// errFolderIdentity is the refusal (409) of a run whose folder root is not
// the stored one (a folder change: the up records it): swapped (see
// differentDirectory) says so; else the device number changed, likely a
// reboot (btrfs, LVM), which Re-check identity fixes.
func errFolderIdentity(name string, swapped bool) error {
	kind := changeIdentity
	if swapped {
		kind = changeSwapped
	}
	return &StatusError{Status: http.StatusConflict, Err: folderChangedError{name: name, kind: kind}}
}

// identityText / swappedText are the messages of a device-only and of an
// inode mismatch (the fixer's own refusals use the same words).
const (
	identityText = folderfix.DeviceChangedText
	swappedText  = folderfix.SwappedText
)

// identityDetail is a probe's detail for a root that isn't the stored one.
func identityDetail(dev, ino, storedDev, storedIno uint64, swapped bool) string {
	if !swapped {
		return fmt.Sprintf("the folder's device number changed (device %d, stored %d; inode %d)", dev, storedDev, ino)
	}
	return fmt.Sprintf("the folder is another directory (device %d inode %d, stored %d %d)", dev, ino, storedDev, storedIno)
}

// PreviewRecheck probes and scans folder id's path (the path rules again,
// no symlink component, a refused filesystem 409) under its folder lock
// (busy: 409) and answers the stored and the current identity. Nothing
// changes.
func (h *Hub) PreviewRecheck(ctx context.Context, id string) (*IdentityCheck, error) {
	unlock, err := h.folderLock(id)
	if err != nil {
		return nil, err
	}
	defer unlock()
	return h.computeRecheck(ctx, id)
}

// ApplyRecheck stores the identity a re-check finds now, when its
// preview's hash is still planHash (else 409: preview again). It holds
// the folder lock and every user instance's app lock (folderLock →
// lockApp: no up, apply or undo of a user runs meanwhile), refuses while
// an interrupted operation awaits recovery, and saves under mu only if
// the definition is still the one previewed. Audited folder.update
// ("recheck …"). A different directory (another inode) needs
// confirmDifferent (400 otherwise) and clears last_apply; a device-only
// change keeps last_apply, recording the root its snapshot names.
func (h *Hub) ApplyRecheck(ctx context.Context, id string, planHash string, confirmDifferent bool, actor directory.Actor) (view *FolderView, err error) {
	detail := ""
	defer func() {
		if detail != "" || err != nil {
			h.auditFolder(actor, "folder.update", id, detail, err)
		}
	}()
	unlock, err := h.folderLock(id)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := h.markerPending(id); err != nil {
		return nil, err
	}
	h.mu.RLock()
	_, ok := h.st.Folders[id]
	users := h.folderUserIDsLocked(id)
	h.mu.RUnlock()
	if !ok {
		return nil, ErrNotFound
	}
	unlockApps, err := h.lockApps(users)
	if err != nil {
		return nil, err
	}
	defer unlockApps()
	c, err := h.computeRecheck(ctx, id)
	if err != nil {
		return nil, err
	}
	if planHash == "" || subtle.ConstantTimeCompare([]byte(c.Hash), []byte(planHash)) != 1 {
		return nil, statusErr(http.StatusConflict, "shared folder %s changed since the re-check's preview: re-check it again", id)
	}
	if c.DifferentDirectory && !confirmDifferent {
		return nil, statusErr(http.StatusBadRequest, "shared folder %s: %s; storing it needs a second confirmation (confirm_different_directory) and forgets the last apply", id, swappedText)
	}

	h.mu.Lock()
	f, ok := h.st.Folders[id]
	switch {
	case !ok:
		h.mu.Unlock()
		return nil, ErrNotFound
	case f.Path != c.Path || f.Dev != c.Old.Dev || f.Ino != c.Old.Ino || f.MountRoot != c.Old.MountRoot ||
		!slices.Equal(h.folderUserIDsLocked(id), users):
		h.mu.Unlock()
		return nil, statusErr(http.StatusConflict, "shared folder %s changed since the re-check's preview: re-check it again", id)
	}
	if err := h.sameDirLocked(c.New.Dev, c.New.Ino, id); err != nil {
		h.mu.Unlock()
		return nil, err
	}
	prev := f
	cleared := false
	switch {
	case c.DifferentDirectory && f.LastApply != nil:
		// Its snapshot is of the old directory: undo is meaningless.
		f.LastApply, cleared = nil, true
	case c.Changed && f.LastApply != nil && f.LastApply.RootDev == 0 && f.LastApply.RootIno == 0:
		// Follow-up (a): the snapshot names the root as it was.
		la := *f.LastApply
		la.RootDev, la.RootIno, la.RootMountRoot = c.Old.Dev, c.Old.Ino, c.Old.MountRoot
		f.LastApply = &la
	}
	f.Dev, f.Ino, f.MountRoot = c.New.Dev, c.New.Ino, c.New.MountRoot
	h.st.Folders[id] = f
	if err := h.saveStateLocked(); err != nil {
		h.st.Folders[id] = prev
		h.mu.Unlock()
		return nil, err
	}
	v := h.folderViewLocked(id)
	h.mu.Unlock()

	detail = "recheck unchanged"
	if c.Changed {
		detail = fmt.Sprintf("recheck device %d→%d inode %d→%d mount_root %s→%s",
			c.Old.Dev, c.New.Dev, c.Old.Ino, c.New.Ino, clip(c.Old.MountRoot, 200), clip(c.New.MountRoot, 200))
		if c.DifferentDirectory {
			detail += " different_directory"
		}
		if cleared {
			detail += " last_apply cleared"
		}
	}
	h.fillLastOp(&v)
	return &v, nil
}

// folderUserIDsLocked are the instances that use folder id (sorted).
// Caller holds mu.
func (h *Hub) folderUserIDsLocked(id string) []string {
	var out []string
	for _, u := range h.folderUsesLocked(id) {
		if !slices.Contains(out, u.Instance) {
			out = append(out, u.Instance)
		}
	}
	slices.Sort(out)
	return out
}

// computeRecheck is the re-check of folder id (fixer runs, never under
// mu): the path rules, the probe, the scan, the filesystem.
func (h *Hub) computeRecheck(ctx context.Context, id string) (*IdentityCheck, error) {
	h.mu.RLock()
	f, ok := h.st.Folders[id]
	users := h.folderUserIDsLocked(id)
	h.mu.RUnlock()
	if !ok {
		return nil, ErrNotFound
	}
	if err := h.folderPathRule(f.Path); err != nil {
		return nil, err
	}
	if err := h.dockerRootRule(ctx, f.Path); err != nil {
		return nil, err
	}
	h.mu.RLock()
	err := h.checkFolderPathLocked(f.Path, id)
	h.mu.RUnlock()
	if err != nil {
		return nil, err
	}
	_, rep, _, err := h.probeAndCheck(ctx, id, f.Path, false)
	if err != nil {
		return nil, err
	}
	c := &IdentityCheck{Folder: id, Path: f.Path,
		Old:    FolderIdentity{Dev: f.Dev, Ino: f.Ino, MountRoot: f.MountRoot},
		New:    FolderIdentity{Dev: rep.Dev, Ino: rep.Ino, MountRoot: rep.MountRoot},
		FSType: rep.FSType, Files: rep.Files, Dirs: rep.Dirs, Partial: rep.Partial}
	c.Changed = c.Old != c.New
	c.DifferentDirectory = c.Changed && differentDirectory(c.Old.Dev, c.Old.Ino, c.Old.MountRoot, c.New.Dev, c.New.Ino, c.New.MountRoot)
	show := func(i FolderIdentity) string {
		return fmt.Sprintf("device %d, inode %d, mounted from `%s`", i.Dev, i.Ino, i.MountRoot)
	}
	c.Lines = []string{"Stored: " + show(c.Old) + ".", "Now: " + show(c.New) + "."}
	counts := message.NewPrinter(language.English).Sprintf("`%s` holds %d %s and %d %s on %s", f.Path, c.Files, plural(c.Files, "file", "files"), c.Dirs, plural(c.Dirs, "folder", "folders"), c.FSType)
	if c.Partial {
		counts += " (a partial count)"
	}
	c.Lines = append(c.Lines, counts+".")
	switch {
	case !c.Changed:
		c.Lines = append(c.Lines, "The folder's identity is as stored: nothing to re-check.")
	case c.DifferentDirectory:
		why := "The inode changed"
		if c.Old.Ino == c.New.Ino {
			why = "The device number and the mount root changed (a filesystem or subvolume root keeps its inode, so the same inode proves nothing)"
		}
		l := why + ": " + swappedText + ". Store it only if you know why (a restored backup, a re-created volume): it needs a second confirmation; nothing on disk changes, but the apps that use the folder will mount what is there now."
		if f.LastApply != nil {
			l += " The last apply is forgotten: Undo last fix is no longer offered (its snapshot is of the old directory)."
		}
		c.Lines = append(c.Lines, l)
	case c.Old.Dev != c.New.Dev:
		c.Lines = append(c.Lines, "Only the device number changed (same inode, same mount root): typical after a reboot on btrfs or LVM. Re-checking stores the new one; nothing on disk changes.")
	default:
		c.Lines = append(c.Lines, "Only the mount root changed (same device number and inode): the path may now be mounted from elsewhere. Store it only if you know why; nothing on disk changes.")
	}
	if len(users) > 0 {
		c.Lines = append(c.Lines, "Used by "+strings.Join(users, ", ")+": none of them is restarted.")
	}
	c.Hash = doctor.Digest([]any{"recheck", id, f.Path, c.Old, c.New, users})
	return c, nil
}
