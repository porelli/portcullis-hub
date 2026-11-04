package hub

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"path"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
	"golang.org/x/text/unicode/norm"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/doctor"
	"github.com/portcullis/hub/internal/folderfix"
	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// Shared folder definitions (contract §14.1): id, name, description and
// host path, one gid each (allocated from FolderGIDMin–FolderGIDMax, lowest
// free first, never reused; or adopted), the path rules, check path. Uses
// are derived from the setting values (folder:<id>[/<subpath>]), never
// stored. The probe and the check run outside mu; every save re-checks
// under mu. Disk changes (assign, apply, undo) are Task 8's.

// The allocated folder gid range.
const FolderGIDMin, FolderGIDMax = state.FolderGIDMin, state.FolderGIDMax

// Scan caps (P10, ruling 38): scheduled scans stop after scanMaxEntries
// entries or scanMaxTime; previews and check path after previewMaxTime.
const (
	scanMaxEntries = 2_000_000
	scanMaxTime    = 10 * time.Minute
	previewMaxTime = 30 * time.Second
)

// opKeyFolder is a folder's op record key (P9): instance ids can't start
// with "_" or contain ".".
func opKeyFolder(id string) string { return "_folder." + id }

// folderPathMax caps a folder's host path (bytes).
const folderPathMax = 4096

// refusedFS: filesystems where the Hub can't keep ownership consistent
// (contract §14.1; folderfix.FSName names smb2 "cifs").
var refusedFS = map[string]string{
	"nfs":      "the file server decides ownership and permissions there",
	"cifs":     "the SMB server decides ownership and permissions there",
	"fuse":     "a userspace driver decides ownership and permissions there",
	"overlay":  "it is a container's layered filesystem",
	"tmpfs":    "it lives in memory and is gone after a reboot",
	"9p":       "the host sharing it (WSL, a VM's host) decides ownership and permissions there",
	"virtiofs": "the VM's host decides ownership and permissions there",
	"ceph":     "the cluster decides ownership and permissions there",
	"ramfs":    "it lives in memory and is gone after a reboot",
	"ecryptfs": "it is a stacked filesystem over another one, which decides the real ownership",
}

// writableFS: the filesystems the fixer writes to (contract §14.2).
var writableFS = map[string]bool{"ext4": true, "xfs": true, "btrfs": true, "zfs": true}

// FolderInput is a create or update request. GID adopts an existing host
// group (create only); Create makes a missing path through the probe.
type FolderInput struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Path        string `json:"path"`
	Description string `json:"description"`
	GID         *int   `json:"gid,omitempty"`
	Create      bool   `json:"create"`
}

// PathCheck is check path's answer (contract §14.1).
type PathCheck struct {
	Path    string                 `json:"path"`
	Exists  bool                   `json:"exists"`
	Created bool                   `json:"created"`
	FSType  string                 `json:"fs_type"`
	ACL     bool                   `json:"acl"`
	Xattr   bool                   `json:"xattr"`
	Files   int64                  `json:"files"`
	Dirs    int64                  `json:"dirs"`
	Partial bool                   `json:"partial"`
	Owners  []folderfix.OwnerCount `json:"owners"`
	// Problems are refusals in plain words (a refused filesystem, an
	// overlap with another folder).
	Problems []string `json:"problems,omitempty"`
	// Summary: "exists · ext4 · ACLs and xattrs supported · 12,410 files ·
	// owners 1000:1000 (all)".
	Summary string `json:"summary"`
}

// FolderView is a folder as the API shows it.
type FolderView struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Path        string          `json:"path"`
	Description string          `json:"description"`
	GID         int             `json:"gid"`
	Adopted     bool            `json:"adopted"`
	Uses        []FolderUseView `json:"uses"`
	LastOp      *OpRecord       `json:"last_op,omitempty"`
	// LastCheck is the folder's last disk scan (doctorscan.go: on demand,
	// after an apply, daily).
	LastCheck *doctor.ScanSummary `json:"last_check,omitempty"`
}

// FolderUseView is one setting value naming the folder. Access is the
// template's folder.access, or for a template without a folder block
// "read" unless the admin confirmed write (WriteConfirmed).
type FolderUseView struct {
	Instance string `json:"instance"`
	Key      string `json:"key"`
	Label    string `json:"label"`
	Subpath  string `json:"subpath"`
	Access   string `json:"access"`
	Declared bool   `json:"declared"`
	ReadOnly bool   `json:"read_only"`
}

// folderLock serialises a folder's operations (try-lock: busy = 409).
// Lock order: folderLock → lockApp → deliverLock (ruling 4).
func (h *Hub) folderLock(id string) (func(), error) {
	m, _ := h.folderLocks.LoadOrStore(id, &sync.Mutex{})
	mu := m.(*sync.Mutex)
	if !mu.TryLock() {
		return nil, &StatusError{Status: http.StatusConflict, Err: ErrBusy{ID: "shared folder " + id}}
	}
	return mu.Unlock, nil
}

// ── the folder source (FolderSource) ─────────────────────

// hubFolders resolves folder:<id>[/<sub>] from state. The caller holds
// mu (project 1 calls it from renderOverrideLocked / PathUsages): it
// never locks and only reads (P8).
type hubFolders struct{ h *Hub }

func (f hubFolders) FolderHostPath(id, sub string) (string, error) {
	fo, ok := f.h.st.Folders[id]
	if !ok {
		return "", fmt.Errorf("no shared folder %q", id)
	}
	return joinFolderPath(fo.Path, sub)
}

// folderPaths is a copy of the folders' paths, for callers that resolve
// outside mu (configCheck).
type folderPaths map[string]string

func (f folderPaths) FolderHostPath(id, sub string) (string, error) {
	p, ok := f[id]
	if !ok {
		return "", fmt.Errorf("no shared folder %q", id)
	}
	return joinFolderPath(p, sub)
}

// joinFolderPath is root/sub for a clean relative sub (settings.ParseFolderRef
// checked it; checked again here).
func joinFolderPath(root, sub string) (string, error) {
	if sub == "" {
		return root, nil
	}
	if strings.HasPrefix(sub, "/") || path.Clean(sub) != sub || HasDotDot(sub) || templates.HasControlChars(sub) {
		return "", fmt.Errorf("subpath %q must be clean and relative", sub)
	}
	return path.Join(root, sub), nil
}

// folderSourceLocked is h.folders for a caller that releases mu before
// resolving: a copy of the folders' paths when it is the Hub's own.
func (h *Hub) folderSourceLocked() FolderSource {
	if _, ok := h.folders.(hubFolders); !ok {
		return h.folders
	}
	m := make(folderPaths, len(h.st.Folders))
	for id, f := range h.st.Folders {
		m[id] = f.Path
	}
	return m
}

// ── path rules ───────────────────────────────────────────

// foldPath is p NFC-normalised and case-folded: the form two spellings
// of one directory share on a case-insensitive or normalising filesystem
// (ZFS casesensitivity=insensitive, ext4 casefold, macOS-style NFD).
// Refusal rules compare it as well as p itself (fail closed); acceptance
// (under a bind root) never uses it.
func foldPath(p string) string {
	return cases.Fold().String(norm.NFC.String(p))
}

// pathsNear: p is at, above or under q, as given or folded.
func pathsNear(p, q string) bool {
	if pathUnder(p, q) || pathUnder(q, p) {
		return true
	}
	fp, fq := foldPath(p), foldPath(q)
	return pathUnder(fp, fq) || pathUnder(fq, fp)
}

func badPath(format string, args ...any) error {
	return statusErr(http.StatusBadRequest, format, args...)
}

// cleanFolderPath is p cleaned (a trailing "/" or "//" normalised), or
// why it can't be a folder path: absolute, no "..", ":", "$" or control
// characters (contract §14.1).
func cleanFolderPath(p string) (string, error) {
	switch {
	case p == "":
		return "", badPath("a shared folder needs a host path")
	case len(p) > folderPathMax:
		return "", badPath("the host path is longer than %d bytes", folderPathMax)
	case templates.HasControlChars(p) || !utf8.ValidString(p):
		return "", badPath("the host path %q has control characters", clip(p, 200))
	case !strings.HasPrefix(p, "/"):
		return "", badPath("the host path %q must be absolute", clip(p, 200))
	case strings.Contains(p, ":"):
		return "", badPath("the host path %s must not contain \":\"", clip(p, 200))
	case strings.Contains(p, "$"):
		return "", badPath("the host path %s must not contain \"$\"", clip(p, 200))
	case HasDotDot(p):
		return "", badPath("the host path %s must not contain \"..\"", clip(p, 200))
	}
	// Invisible and lookalike characters (format characters, spaces other
	// than ASCII's) would show a path as another one in the UI and the
	// audit; so would a component that starts or ends with a space.
	for _, r := range p {
		if unicode.Is(unicode.Cf, r) || (unicode.Is(unicode.Zs, r) && r != ' ') {
			return "", badPath("the host path %q has an invisible or lookalike character (U+%04X)", clip(p, 200), r)
		}
	}
	for _, seg := range strings.Split(p, "/") {
		if seg != strings.TrimSpace(seg) {
			return "", badPath("the host path %q has a component that starts or ends with a space", clip(p, 200))
		}
	}
	c := path.Clean(p)
	if c == "/" {
		return "", badPath("the host's root directory can't be a shared folder: choose a folder below a bind root (%s)", "HUB_OVERRIDE_BIND_ROOTS")
	}
	return c, nil
}

// folderPathRule checks a clean path against the configuration: not a
// system or sensitive path, not at, above or under the core checkout or
// the data files' host directory, strictly under a bind root. It needs no
// lock (configuration only).
func (h *Hub) folderPathRule(p string) error {
	for _, sys := range systemRoots {
		if pathsNear(p, sys) {
			return badPath("%s is (or contains) the system path %s", p, sys)
		}
	}
	for _, s := range sensitiveHostPaths {
		if pathsNear(p, s) {
			return badPath("%s is (or contains) the sensitive path %s", p, s)
		}
	}
	if slices.Contains(h.bindRoots, p) {
		return badPath("%s is a bind root itself: choose a folder below it", p)
	}
	if core := path.Clean(h.cfg.ProjectHostDir); h.cfg.ProjectHostDir != "" && pathsNear(p, core) {
		return badPath("%s overlaps the Portcullis core checkout %s", p, core)
	}
	if af := path.Clean(h.cfg.AppFilesHostDir); h.cfg.AppFilesHostDir != "" && pathsNear(p, af) {
		return badPath("%s overlaps the settings data files directory %s", p, af)
	}
	if root, _ := h.bindRootOf(p); root == "" {
		return badPath("%s is not under a bind root (%s; HUB_OVERRIDE_BIND_ROOTS)", p, strings.Join(h.bindRoots, ", "))
	}
	return nil
}

// dockerRootRule: p is not at, above or under the daemon's data root
// (Info DockerRootDir, wherever it was moved: image layers, containers,
// volumes, the Hub's own state). Unreadable = 503. No lock held.
func (h *Hub) dockerRootRule(ctx context.Context, p string) error {
	if h.engine == nil {
		return statusErr(http.StatusServiceUnavailable, "shared folders need the Docker Engine API")
	}
	root, err := h.engine.DockerRootDir(ctx)
	if err != nil {
		return statusErr(http.StatusServiceUnavailable, "shared folders: can't read Docker's data root: %v", err)
	}
	if !path.IsAbs(root) || path.Clean(root) != root || root == "/" {
		return statusErr(http.StatusServiceUnavailable, "shared folders: Docker reports the data root %q, not an absolute directory", clip(root, 200))
	}
	if pathsNear(p, root) {
		return badPath("%s is (or contains) Docker's data root %s", p, root)
	}
	return nil
}

// bindRootOf is the bind root strictly above p and p relative to it ("",
// "" if none).
func (h *Hub) bindRootOf(p string) (root, rel string) {
	for _, r := range h.bindRoots {
		if p != r && pathUnder(p, r) {
			return r, strings.TrimPrefix(p, r+"/")
		}
	}
	return "", ""
}

// overlapLocked: p at, above or under another folder than selfID (409).
func (h *Hub) overlapLocked(p, selfID string) error {
	ids := make([]string, 0, len(h.st.Folders))
	for id := range h.st.Folders {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		f := h.st.Folders[id]
		if id != selfID && pathsNear(p, f.Path) {
			return statusErr(http.StatusConflict, "%s overlaps shared folder %s (%s): folders can't be at or under each other", p, id, f.Path)
		}
	}
	return nil
}

// sameDirLocked: a folder other than selfID whose root is dev/ino — the
// same directory through another path (a host bind mount, another
// spelling on a case-insensitive filesystem): 409. dev 0 = not probed.
func (h *Hub) sameDirLocked(dev, ino uint64, selfID string) error {
	if dev == 0 {
		return nil
	}
	for id, f := range h.st.Folders {
		if id != selfID && f.Dev == dev && f.Ino == ino {
			return statusErr(http.StatusConflict, "this directory is already shared folder %s (%s), reached through another path", id, f.Path)
		}
	}
	return nil
}

// checkFolderPathLocked is every path rule a save checks under mu: the
// configuration's (folderPathRule) and no overlap with another folder.
func (h *Hub) checkFolderPathLocked(p, selfID string) error {
	if err := h.folderPathRule(p); err != nil {
		return err
	}
	return h.overlapLocked(p, selfID)
}

// ── probe and check (fixer runs; never under mu) ─────────

// probePath probes p below its bind root (contract §14.2): a symlink
// component is 409. folder labels the run ("" = path-check).
func (h *Hub) probePath(ctx context.Context, p string, create bool, folder string) (*folderfix.ProbeReport, error) {
	root, rel := h.bindRootOf(p)
	if root == "" {
		return nil, badPath("%s is not under a bind root", p)
	}
	rep, err := h.runProbe(ctx, fixerRun{Mode: "probe", Folder: folder, Source: root, Extra: folderfix.ArgsExtra{Rel: rel, Create: create}})
	if err != nil {
		return nil, err
	}
	if rep.Symlink != "" {
		link := path.Join(root, rep.Symlink)
		if !pathUnder(p, link) {
			return nil, statusErr(http.StatusInternalServerError, "shared folder probe: symlink %q is not on the path", rep.Symlink)
		}
		return nil, statusErr(http.StatusConflict, "%s is a symlink; give the real path", link)
	}
	if rep.Exists && (rep.Dev == 0 || rep.Ino == 0) {
		return nil, statusErr(http.StatusInternalServerError, "shared folder probe: no device or inode for %s", p)
	}
	return rep, nil
}

// probeFolder: p's device and inode (a symlink component: 409).
func (h *Hub) probeFolder(ctx context.Context, p string, create bool) (dev, ino uint64, exists bool, err error) {
	rep, err := h.probePath(ctx, p, create, "")
	if err != nil {
		return 0, 0, false, err
	}
	return rep.Dev, rep.Ino, rep.Exists, nil
}

// scanPath scans p (bound at /folder) with the preview caps; the root
// must be the probe's dev / ino (the fixer refuses another, and the Hub
// checks its report too).
func (h *Hub) scanPath(ctx context.Context, p, folder string, dev, ino uint64) (*folderfix.Report, error) {
	rep, err := h.runFixer(ctx, fixerRun{Mode: "scan", Folder: folder, Source: p,
		Opts: folderfix.Options{ExpectDev: dev, ExpectIno: ino, MaxEntries: scanMaxEntries, MaxTime: previewMaxTime}})
	if err != nil {
		return nil, err
	}
	if rep.Dev != dev || rep.Ino != ino {
		return nil, statusErr(http.StatusConflict, "%s changed while it was checked (device/inode %d/%d, then %d/%d): check it again", p, dev, ino, rep.Dev, rep.Ino)
	}
	if !path.IsAbs(rep.MountRoot) || templates.HasControlChars(rep.MountRoot) {
		return nil, statusErr(http.StatusInternalServerError, "shared folder check: the fixer reported no mount root for %s", p)
	}
	return rep, nil
}

// fsProblem: why the Hub refuses to manage a folder on fs ("" = it doesn't).
func fsProblem(p, fs string) string {
	if why, ok := refusedFS[fs]; ok {
		return fmt.Sprintf("%s is on %s: the Hub can't keep its ownership consistent there (%s)", p, fs, why)
	}
	return ""
}

// CheckFolderPath probes path (creating it with create) and scans it
// with the preview caps (contract §14.1). Path rules are refusals (400)
// before any run; a symlink component is 409; an overlap with a folder
// and a refused filesystem are Problems.
func (h *Hub) CheckFolderPath(ctx context.Context, p string, create bool) (*PathCheck, error) {
	c, err := cleanFolderPath(p)
	if err != nil {
		return nil, err
	}
	if err := h.folderPathRule(c); err != nil {
		return nil, err
	}
	if err := h.dockerRootRule(ctx, c); err != nil {
		return nil, err
	}
	h.mu.RLock()
	overlap := h.overlapLocked(c, "")
	h.mu.RUnlock()
	// Never create a directory inside (or above) another folder.
	pr, err := h.probePath(ctx, c, create && overlap == nil, "")
	if err != nil {
		return nil, err
	}
	pc := &PathCheck{Path: c, Exists: pr.Exists, Created: pr.Created, FSType: pr.FSType, Owners: []folderfix.OwnerCount{}}
	if overlap != nil {
		pc.Problems = append(pc.Problems, overlap.Error())
	}
	h.mu.RLock()
	same := h.sameDirLocked(pr.Dev, pr.Ino, "")
	h.mu.RUnlock()
	if same != nil {
		pc.Problems = append(pc.Problems, same.Error())
	}
	if !pr.Exists {
		pc.Summary = "missing"
		return pc, nil
	}
	rep, err := h.scanPath(ctx, c, "", pr.Dev, pr.Ino)
	if err != nil {
		return nil, err
	}
	pc.FSType, pc.ACL, pc.Xattr = rep.FSType, rep.ACL, rep.Xattr
	pc.Files, pc.Dirs, pc.Partial = rep.Files, rep.Dirs, rep.Partial
	if rep.Owners != nil {
		pc.Owners = rep.Owners
	}
	if why := fsProblem(c, pc.FSType); why != "" {
		pc.Problems = append(pc.Problems, why)
	}
	pc.Summary = pathSummary(pc, rep.Entries)
	return pc, nil
}

// pathSummary: "exists · ext4 · ACLs and xattrs supported · 12,410 files ·
// owners 1000:1000 (all)".
func pathSummary(pc *PathCheck, entries int64) string {
	pr := message.NewPrinter(language.English)
	parts := []string{"exists"}
	if pc.Created {
		parts[0] = "created"
	}
	parts = append(parts, pc.FSType)
	switch {
	case pc.ACL && pc.Xattr:
		parts = append(parts, "ACLs and xattrs supported")
	case pc.Xattr:
		parts = append(parts, "xattrs supported, no ACLs")
	case pc.ACL:
		parts = append(parts, "ACLs supported, no xattrs")
	default:
		parts = append(parts, "no ACL or xattr support")
	}
	files := pr.Sprintf("%d files", pc.Files)
	if pc.Partial {
		files = pr.Sprintf("%d+ files (partial check)", pc.Files)
	}
	parts = append(parts, files)
	if len(pc.Owners) > 0 {
		if o := pc.Owners[0]; o.N == entries && !pc.Partial {
			parts = append(parts, fmt.Sprintf("owners %d:%d (all)", o.UID, o.GID))
		} else {
			var os []string
			for i, o := range pc.Owners {
				if i == 3 {
					os = append(os, "…")
					break
				}
				os = append(os, fmt.Sprintf("%d:%d (%s)", o.UID, o.GID, pr.Sprintf("%d", o.N)))
			}
			parts = append(parts, "owners "+strings.Join(os, ", "))
		}
	}
	return strings.Join(parts, " · ")
}

// ── definitions ──────────────────────────────────────────

// checkFolderFields: the name (required, ≤ 64, one line) and description
// (≤ 500) of contract §14.1.
func checkFolderFields(in FolderInput) error {
	switch {
	case in.Name == "":
		return badPath("a shared folder needs a name")
	case utf8.RuneCountInString(in.Name) > state.FolderNameMax:
		return badPath("the name is longer than %d characters", state.FolderNameMax)
	case templates.HasControlChars(in.Name) || !utf8.ValidString(in.Name):
		return badPath("the name must be one line without control characters")
	case utf8.RuneCountInString(in.Description) > state.FolderDescriptionMax:
		return badPath("the description is longer than %d characters", state.FolderDescriptionMax)
	case templates.HasControlChars(in.Description) || !utf8.ValidString(in.Description):
		return badPath("the description must not contain control characters")
	}
	return nil
}

// nextGIDLocked is the lowest gid of the range never allocated (0: none).
func (h *Hub) nextGIDLocked() int {
	for g := FolderGIDMin; g <= FolderGIDMax; g++ {
		if _, used := slices.BinarySearch(h.st.FolderGIDs, g); !used {
			return g
		}
	}
	return 0
}

// gidUserLocked is the folder (other than selfID) whose gid is gid.
func (h *Hub) gidUserLocked(gid int, selfID string) string {
	for id, f := range h.st.Folders {
		if id != selfID && f.GID == gid {
			return id
		}
	}
	return ""
}

func errNoFreeGID() error {
	return statusErr(http.StatusConflict, "no free folder group: every gid of %d-%d has been allocated (gids are never reused); adopt an existing group by number instead", FolderGIDMin, FolderGIDMax)
}

// createChecksLocked: what a create re-checks under mu.
func (h *Hub) createChecksLocked(in FolderInput, p string, dev, ino uint64) error {
	if _, ok := h.st.Folders[in.ID]; ok {
		return statusErr(http.StatusConflict, "shared folder %s already exists", in.ID)
	}
	if err := h.checkFolderPathLocked(p, in.ID); err != nil {
		return err
	}
	if err := h.sameDirLocked(dev, ino, in.ID); err != nil {
		return err
	}
	if in.GID != nil {
		if other := h.gidUserLocked(*in.GID, in.ID); other != "" {
			return statusErr(http.StatusConflict, "gid %d is already shared folder %s's group", *in.GID, other)
		}
	} else if h.nextGIDLocked() == 0 {
		return errNoFreeGID()
	}
	return nil
}

// probeAndCheck runs the probe and the check of p for folder id (outside
// mu): it must exist (or be created), be no symlink, not on a refused
// filesystem. Warnings: a filesystem the fixer won't write to.
func (h *Hub) probeAndCheck(ctx context.Context, id, p string, create bool) (*folderfix.ProbeReport, *folderfix.Report, []string, error) {
	pr, err := h.probePath(ctx, p, create, id)
	if err != nil {
		return nil, nil, nil, err
	}
	if !pr.Exists {
		return nil, nil, nil, statusErr(http.StatusConflict, "%s doesn't exist: create it, or ask the Hub to (create)", p)
	}
	rep, err := h.scanPath(ctx, p, id, pr.Dev, pr.Ino)
	if err != nil {
		return nil, nil, nil, err
	}
	for _, fs := range []string{rep.FSType, pr.FSType} {
		if why := fsProblem(p, fs); why != "" {
			return nil, nil, nil, statusErr(http.StatusConflict, "%s", why)
		}
	}
	var warns []string
	if !writableFS[rep.FSType] {
		warns = append(warns, fmt.Sprintf("%s is on %s: the Hub can check it, but fixes its ownership only on ext4, xfs, btrfs and zfs", p, rep.FSType))
	} else if !rep.ACL {
		warns = append(warns, fmt.Sprintf("%s has no ACL support: a fix sets the group, setgid and modes only", p))
	}
	return pr, rep, warns, nil
}

// CreateFolder defines a shared folder (contract §14.1): the fields and
// path rules, then the probe (creating the path with in.Create) and the
// check outside mu, then under mu the same checks again (a lost race is
// 409), the gid (in.GID adopted, else the lowest never allocated, added
// to folder_gids) and the save. The answer's warnings: an adopted gid's,
// a filesystem the fixer won't write to.
func (h *Hub) CreateFolder(ctx context.Context, in FolderInput, actor string) (view *FolderView, warnings []string, err error) {
	detail := ""
	defer func() { h.auditFolder(actor, "folder.create", in.ID, detail, err) }()
	if !settings.FolderIDRe.MatchString(in.ID) {
		return nil, nil, badPath("the folder id must match %s", settings.FolderIDRe)
	}
	if err := checkFolderFields(in); err != nil {
		return nil, nil, err
	}
	p, err := cleanFolderPath(in.Path)
	if err != nil {
		return nil, nil, err
	}
	if in.GID != nil {
		if why := state.ValidAdoptedGID(*in.GID); why != "" {
			return nil, nil, badPath("gid %d can't be adopted: %s", *in.GID, why)
		}
	}
	if err := h.folderPathRule(p); err != nil {
		return nil, nil, err
	}
	if err := h.dockerRootRule(ctx, p); err != nil {
		return nil, nil, err
	}
	h.mu.RLock()
	err = h.createChecksLocked(in, p, 0, 0)
	h.mu.RUnlock()
	if err != nil {
		return nil, nil, err
	}
	unlock, err := h.folderLock(in.ID)
	if err != nil {
		return nil, nil, err
	}
	defer unlock()
	pr, rep, warns, err := h.probeAndCheck(ctx, in.ID, p, in.Create)
	if err != nil {
		return nil, nil, err
	}

	// A lost race leaves what the probe created (in.Create): an empty
	// directory owned by the bind root's owner, no folder (contract §14.1).
	h.mu.Lock()
	if err := h.createChecksLocked(in, p, pr.Dev, pr.Ino); err != nil {
		h.mu.Unlock()
		return nil, nil, err
	}
	f := state.Folder{Name: in.Name, Path: p, Description: in.Description, CreatedAt: time.Now().UTC(),
		Dev: pr.Dev, Ino: pr.Ino, MountRoot: rep.MountRoot}
	if in.GID != nil {
		f.GID, f.Adopted = *in.GID, true
	}
	gidAt := -1
	if !f.Adopted {
		f.GID = h.nextGIDLocked()
		gidAt, _ = slices.BinarySearch(h.st.FolderGIDs, f.GID)
		h.st.FolderGIDs = slices.Insert(h.st.FolderGIDs, gidAt, f.GID)
	}
	if h.st.Folders == nil {
		h.st.Folders = map[string]state.Folder{}
	}
	h.st.Folders[in.ID] = f
	if err := h.saveStateLocked(); err != nil {
		// Never defined: nothing used the gid, so taking it back keeps
		// "never reused" (no file has it).
		delete(h.st.Folders, in.ID)
		if gidAt >= 0 {
			h.st.FolderGIDs = slices.Delete(h.st.FolderGIDs, gidAt, gidAt+1)
		}
		h.mu.Unlock()
		return nil, nil, err
	}
	v := h.folderViewLocked(in.ID)
	h.mu.Unlock()

	detail = fmt.Sprintf("gid=%d path=%s", f.GID, p)
	if f.Adopted {
		detail = fmt.Sprintf("gid=%d adopted path=%s", f.GID, p)
		warns = append([]string{fmt.Sprintf("anything mounted with gid %d becomes reachable by this folder's apps", f.GID)}, warns...)
	}
	h.fillLastOp(&v)
	return &v, warns, nil
}

// usesText lists uses for a refusal: "immich (library), samba (share)".
func usesText(uses []FolderUseView) string {
	var s []string
	for _, u := range uses {
		s = append(s, fmt.Sprintf("%s (%s)", u.Instance, u.Key))
	}
	return strings.Join(s, ", ")
}

// UpdateFolder changes a folder's name and description at any time and
// its path while no instance uses it (409 otherwise; the probe and check
// run again and the root's device, inode and mount root are stored again,
// R41/R43; the last apply is forgotten: its snapshot is of another tree).
// The id and gid never change (400). in.Path "" keeps the path.
func (h *Hub) UpdateFolder(ctx context.Context, id string, in FolderInput, actor string) (view *FolderView, err error) {
	detail := ""
	defer func() { h.auditFolder(actor, "folder.update", id, detail, err) }()
	if in.ID != "" && in.ID != id {
		return nil, badPath("a shared folder's id can't change")
	}
	if err := checkFolderFields(in); err != nil {
		return nil, err
	}
	p := ""
	if in.Path != "" {
		if p, err = cleanFolderPath(in.Path); err != nil {
			return nil, err
		}
	}
	unlock, err := h.folderLock(id)
	if err != nil {
		return nil, err
	}
	defer unlock()
	// changeChecks: the folder exists, the gid stays, and a path change
	// passes the rules while the folder is unused. Under mu.
	changeChecks := func() (state.Folder, bool, error) {
		f, ok := h.st.Folders[id]
		if !ok {
			return f, false, ErrNotFound
		}
		if in.GID != nil && *in.GID != f.GID {
			return f, false, badPath("a shared folder's gid can't change")
		}
		if p == "" || p == f.Path {
			return f, false, nil
		}
		if uses := h.folderUsesLocked(id); len(uses) > 0 {
			return f, true, statusErr(http.StatusConflict, "shared folder %s is used by %s: its path can't change while it is used", id, usesText(uses))
		}
		return f, true, h.checkFolderPathLocked(p, id)
	}
	h.mu.RLock()
	_, moved, err := changeChecks()
	h.mu.RUnlock()
	if err != nil {
		return nil, err
	}
	var pr *folderfix.ProbeReport
	var rep *folderfix.Report
	if moved {
		if err := h.dockerRootRule(ctx, p); err != nil {
			return nil, err
		}
		if pr, rep, _, err = h.probeAndCheck(ctx, id, p, in.Create); err != nil {
			return nil, err
		}
	}

	h.mu.Lock()
	f, movedNow, err := changeChecks()
	if err == nil && movedNow != moved {
		err = statusErr(http.StatusConflict, "shared folder %s changed meanwhile: try again", id)
	}
	if err == nil && moved {
		err = h.sameDirLocked(pr.Dev, pr.Ino, id)
	}
	if err != nil {
		h.mu.Unlock()
		return nil, err
	}
	var changed []string
	if f.Name != in.Name {
		changed = append(changed, "name")
	}
	if f.Description != in.Description {
		changed = append(changed, "description")
	}
	prev := f
	f.Name, f.Description = in.Name, in.Description
	if moved {
		changed = append(changed, "path="+p)
		f.Path, f.Dev, f.Ino, f.MountRoot, f.LastApply = p, pr.Dev, pr.Ino, rep.MountRoot, nil
	}
	h.st.Folders[id] = f
	if err := h.saveStateLocked(); err != nil {
		h.st.Folders[id] = prev
		h.mu.Unlock()
		return nil, err
	}
	v := h.folderViewLocked(id)
	h.mu.Unlock()

	detail = "unchanged"
	if len(changed) > 0 {
		detail = "changed " + strings.Join(changed, " ")
	}
	h.fillLastOp(&v)
	return &v, nil
}

// DeleteFolder removes a folder's definition: 409 while any setting value
// names it (listing them). Files are never touched; its gid stays in
// folder_gids.
func (h *Hub) DeleteFolder(id, actor string) (err error) {
	detail := ""
	defer func() { h.auditFolder(actor, "folder.delete", id, detail, err) }()
	unlock, err := h.folderLock(id)
	if err != nil {
		return err
	}
	defer unlock()
	h.mu.Lock()
	f, ok := h.st.Folders[id]
	if !ok {
		h.mu.Unlock()
		return ErrNotFound
	}
	if uses := h.folderUsesLocked(id); len(uses) > 0 {
		h.mu.Unlock()
		return statusErr(http.StatusConflict, "shared folder %s is used by %s: change those settings first", id, usesText(uses))
	}
	delete(h.st.Folders, id)
	if err := h.saveStateLocked(); err != nil {
		h.st.Folders[id] = f
		h.mu.Unlock()
		return err
	}
	h.mu.Unlock()
	detail = fmt.Sprintf("gid=%d path=%s", f.GID, f.Path)
	return nil
}

// saveStateLocked saves state.yaml; a failure is a 500 (the caller undoes
// its change in memory). Caller holds mu (write).
func (h *Hub) saveStateLocked() error {
	if err := h.st.Save(h.statePath()); err != nil {
		log.Printf("ERROR: save state: %v", err)
		return statusErr(http.StatusInternalServerError, "saving the Hub's state failed (%v): nothing was changed", err)
	}
	return nil
}

// Folders lists the shared folders by id.
func (h *Hub) Folders() []FolderView {
	h.mu.RLock()
	ids := make([]string, 0, len(h.st.Folders))
	for id := range h.st.Folders {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]FolderView, 0, len(ids))
	for _, id := range ids {
		out = append(out, h.folderViewLocked(id))
	}
	h.mu.RUnlock()
	for i := range out {
		h.fillLastOp(&out[i])
	}
	return out
}

// folderViewLocked is folder id's view without its op record.
func (h *Hub) folderViewLocked(id string) FolderView {
	f := h.st.Folders[id]
	return FolderView{ID: id, Name: f.Name, Path: f.Path, Description: f.Description, GID: f.GID, Adopted: f.Adopted,
		Uses: h.folderUsesLocked(id)}
}

// fillLastOp adds the folder's op record (under opsMu, never with mu)
// and its last disk scan.
func (h *Hub) fillLastOp(v *FolderView) {
	h.fillLastCheck(v)
	h.opsMu.Lock()
	defer h.opsMu.Unlock()
	if r, ok := h.ops[opKeyFolder(v.ID)]; ok {
		v.LastOp = &r
	}
}

// folderUsesLocked derives folder id's uses from every instance's
// setting values (instance values, person defaults and rows, group
// records) of path options that name it. A value whose option is
// unknown (template or option gone) still counts: fail closed. Sorted by
// instance, then key.
func (h *Hub) folderUsesLocked(id string) []FolderUseView {
	f := h.st.Folders[id]
	seen := map[string]bool{}
	out := []FolderUseView{}
	for inst, s := range h.st.Settings {
		t := h.findLocked(inst)
		add := func(key string, v any) {
			str, ok := v.(string)
			if !ok {
				return
			}
			ref, sub, ok, err := settings.ParseFolderRef(str)
			if !ok || err != nil || ref != id || seen[inst+"/"+key] {
				return
			}
			var o *templates.Option
			if t != nil {
				o = optionByKey(t, key)
			}
			if o != nil && o.Type != templates.TypePath {
				return
			}
			seen[inst+"/"+key] = true
			u := FolderUseView{Instance: inst, Key: key, Label: key, Subpath: sub, Access: templates.FolderRead}
			if o != nil {
				u.Label = o.Label
			}
			switch {
			case o != nil && o.Folder != nil:
				u.Declared, u.Access = true, o.Folder.Access
			case f.WriteConfirmed[inst+"/"+key]:
				u.Access = templates.FolderWrite
			}
			u.ReadOnly = u.Access != templates.FolderWrite
			out = append(out, u)
		}
		for k, v := range s.Values {
			add(k, v)
		}
		for k, p := range s.Person {
			add(k, p.Default)
			for _, r := range p.Rows {
				add(k, r.Value)
			}
		}
		for k, rows := range s.Groups {
			for _, r := range rows {
				add(k, r.Value)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Instance != out[j].Instance {
			return out[i].Instance < out[j].Instance
		}
		return out[i].Key < out[j].Key
	})
	return out
}

// checkFoldersAtStart refuses folders whose stored path no longer passes
// the path rules of this configuration (bind roots, core checkout, data
// files): the Hub doesn't start on them (P24).
func (h *Hub) checkFoldersAtStart() error {
	for id, f := range h.st.Folders {
		if err := h.folderPathRule(f.Path); err != nil {
			return fmt.Errorf("state.yaml: shared folder %s: %v — fix HUB_OVERRIDE_BIND_ROOTS or the folder, then restart", id, err)
		}
		for other, g := range h.st.Folders {
			if other != id && pathUnder(f.Path, g.Path) {
				return fmt.Errorf("state.yaml: shared folders %s and %s overlap", id, other)
			}
		}
	}
	return nil
}

// auditFolder records a folder operation after mu is released; a 4xx is
// "refused".
func (h *Hub) auditFolder(actor, action, id, detail string, err error) {
	h.mu.RLock()
	a := h.audit
	h.mu.RUnlock()
	if a == nil {
		return
	}
	e := directory.AuditEntry{Actor: actor, Action: action, Target: clip(id, 64), Detail: detail, Result: "ok"}
	if err != nil {
		e.Result, e.Error = "error", err.Error()
		var se *StatusError
		if errors.As(err, &se) && se.Status < 500 {
			e.Result = "refused"
		}
	}
	if aerr := a.Append(e); aerr != nil {
		log.Printf("audit: %v", aerr)
	}
}
