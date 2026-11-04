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
	FSType  string         `json:"fs_type"`
	Files   int64          `json:"files"`
	Dirs    int64          `json:"dirs"`
	Partial bool           `json:"partial"`
	Lines   []string       `json:"lines"`
	// Hash binds the apply to this preview (the folder, its path, both
	// identities and its users).
	Hash string `json:"plan_hash"`
}

// errFolderIdentity is the refusal (409) of a run whose folder root has
// another device, inode or mount root than stored: a folder change (the
// up records it) whose likely cause is a reboot.
func errFolderIdentity(name string) error {
	return &StatusError{Status: http.StatusConflict, Err: folderChangedError{name: name, identity: true}}
}

// identityText is the message a dev / ino / mount-root mismatch carries.
const identityText = "the folder's identity changed (e.g. after a reboot on btrfs/LVM): re-check it in Shared folders"

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
// ("recheck …").
func (h *Hub) ApplyRecheck(ctx context.Context, id, planHash, actor string) (view *FolderView, err error) {
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
	show := func(i FolderIdentity) string {
		return fmt.Sprintf("device %d, inode %d, mounted from `%s`", i.Dev, i.Ino, i.MountRoot)
	}
	c.Lines = []string{"Stored: " + show(c.Old) + ".", "Now: " + show(c.New) + "."}
	counts := message.NewPrinter(language.English).Sprintf("`%s` holds %d files and %d folders on %s", f.Path, c.Files, c.Dirs, c.FSType)
	if c.Partial {
		counts += " (a partial count)"
	}
	c.Lines = append(c.Lines, counts+".")
	switch {
	case !c.Changed:
		c.Lines = append(c.Lines, "The folder's identity is as stored: nothing to re-check.")
	case c.Old.Ino == c.New.Ino && c.Old.MountRoot == c.New.MountRoot:
		c.Lines = append(c.Lines, "Only the device number changed: typical after a reboot on btrfs or LVM. Re-checking stores the new one; nothing on disk changes.")
	default:
		c.Lines = append(c.Lines, "The inode or the mount root changed too: the path may now be another directory. Store it only if you know why (a restored backup, a re-created volume); nothing on disk changes, but the apps that use the folder will mount what is there now.")
	}
	if len(users) > 0 {
		c.Lines = append(c.Lines, "Used by "+strings.Join(users, ", ")+": none of them is restarted.")
	}
	c.Hash = doctor.Digest([]any{"recheck", id, f.Path, c.Old, c.New, users})
	return c, nil
}
