// Package doctor is the Hub's doctor engine (contract §14.5–14.6): the
// finding model, fingerprints, mutes and a registry of checks. It is
// pure: checks judge an Inputs snapshot the Hub gathers and never change
// anything (fixes are previewed and applied by the Hub). Findings name
// instances, folders and paths, never secrets.
package doctor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/portcullis/hub/internal/folderfix"
	"github.com/portcullis/hub/internal/templates"
)

// Severity of a finding (contract §14.5).
type Severity string

const (
	Problem Severity = "problem"
	Warning Severity = "warning"
	Info    Severity = "info"
)

// rank orders severities: Problem first.
func (s Severity) rank() int {
	switch s {
	case Problem:
		return 0
	case Warning:
		return 1
	case Info:
		return 2
	}
	return 3
}

// FixClass is how a finding is fixed (contract §14.6).
type FixClass string

const (
	FixOneClick FixClass = "one_click"
	FixExplain  FixClass = "explain"
	FixLink     FixClass = "link"
	FixNone     FixClass = ""
)

// Link opens the settings panel at an option, or (Tab set, contract
// §14.5 NEW) a tab of the instance — today only "ai" (TabAI).
type Link struct {
	Instance string `json:"instance"`
	Option   string `json:"option"`
	Tab      string `json:"tab,omitempty"`
}

// Finding is one thing the doctor found.
type Finding struct {
	FP        string   `json:"fp"`
	Kind      string   `json:"kind"`
	Severity  Severity `json:"severity"`
	Title     string   `json:"title"`
	Why       string   `json:"why"`
	Fix       string   `json:"fix_text,omitempty"`
	Instances []string `json:"instances,omitempty"`
	Folders   []string `json:"folders,omitempty"`
	Paths     []string `json:"paths,omitempty"`
	Class     FixClass `json:"fix_class,omitempty"`
	FixKind   string   `json:"fix_kind,omitempty"`
	// MoreFixes: other one-click fixes the finding offers besides FixKind
	// (folder_owner: undo_folder while the folder has a last apply); the
	// Hub's PreviewFix / ApplyFix pick one with the param "fix".
	MoreFixes []string `json:"more_fix_kinds,omitempty"`
	Steps     []string `json:"steps,omitempty"` // explain-only instructions
	Link      *Link    `json:"link,omitempty"`
	Partial   bool     `json:"partial,omitempty"`
	// Dismiss: people the finding lists who an administrator dismisses
	// once handled (POST /api/instances/{id}/ai/dismiss; T27).
	Dismiss []Dismiss `json:"dismiss,omitempty"`
	// Inputs is the digest of what produced the finding; Run folds the
	// severity in, so a mute never hides a finding whose severity rose.
	Inputs string `json:"-"`
	// Token is the finding as it was reported (its inputs digest,
	// opaque): a mute carries it back and is refused when the finding
	// changed since (H8).
	Token string `json:"token"`
	Muted *Mute  `json:"muted,omitempty"`
}

// Dismiss is one dismissable person of a finding.
type Dismiss struct {
	Instance  string `json:"instance"`
	Companion string `json:"companion"`
	User      string `json:"user"`
}

// Mute is an admin's mute of a finding: it holds while the finding's
// inputs digest equals Inputs.
type Mute struct {
	Reason string    `json:"reason"`
	Actor  string    `json:"actor"`
	At     time.Time `json:"at"`
	Inputs string    `json:"-"`
}

// PathIn is one host directory an enabled instance mounts (the Hub's
// PathUsage, copied field by field).
type PathIn struct {
	Instance, Key, Label, HostPath, Service, Mount, Access, Source, Folder, Subpath, JoinsGroup, UIDEnv, GIDEnv string
	UID, GID                                                                                                    int
	GIDs                                                                                                        []int
	OwnerKnown, Writes, ReadOnly, MustOwn, Declared                                                             bool
	// PersonTree: a per-person tree (folder.runs_as gid_from, F34): never
	// a shared_path or folder_owner subject.
	PersonTree bool
	Checks     []templates.Check
}

// PathIn sources (the Hub's PathSource*).
const (
	SourceSetting        = "setting"
	SourceFolder         = "folder"
	SourceCustomOverride = "custom_override"
)

// FolderIn is a shared folder and its uses.
type FolderIn struct {
	ID, Name, Path string
	GID            int
	Uses           []PathIn
	LastApply      *time.Time
}

// PortIn is a published port of an enabled instance (Task 10): a
// template port as set in Settings, or a custom-override port (Custom;
// Key and Label those of the template port with the same service and
// container port, LanOnly from it). Port is the host port (a range's
// first), Bind the host address as written ("" = all interfaces).
type PortIn struct {
	Instance, Key, Label, Service, Bind string
	Port, PortEnd, Container            int
	Protocol                            string
	LanOnly, HostNetwork, Custom        bool
}

// RowIn is one bound row of a per-person option. Exists: the row's group
// id still names that group; Members: how many of the instance's
// population are in it (-1: unknown, the directory is unavailable).
type RowIn struct {
	Group   string
	GroupID int
	Exists  bool
	Members int
}

// PersonIn is a per-person option of an enabled instance.
type PersonIn struct {
	Instance, Key, Label, DefaultDisplay string
	Rows                                 []RowIn
	Requires                             *templates.Check
}

// ChangeIn is a recorded folder_changed state (the post-start probe
// found a folder's root or subpath changed).
type ChangeIn struct {
	Instance, Key, Folder, Subpath, Detail string
	At                                     time.Time
}

// ScanIn is a cached disk scan (Task 11): of a shared folder (Folder)
// or a hand-typed host path (Folder ""). Principals are the identities
// the scan judged (their Name: the instance id, or "<instance>.<n>" when
// one instance has several); Err: the scan failed (Report nil).
type ScanIn struct {
	At         time.Time
	Report     *folderfix.Report
	Target     string
	Folder     string
	Principals []folderfix.Principal
	Err        string
	// Tree: a per-person tree's top-level scan (its Children only; the
	// folder checks never judge it).
	Tree bool
}

// RuntimeIn is what a running container's processes hold (Task 11, the
// runtime gid check): every gid of their Gid: and Groups: lines; Err: the
// container couldn't be read (no GIDs; an Info finding).
type RuntimeIn struct {
	Instance, Service, Container string
	GIDs                         []int
	Err                          string
	// PIDsRead / PIDsTotal: the processes read and listed (Total > Read:
	// a partial check, an Info).
	PIDsRead, PIDsTotal int
	// At: when the gids were read (the Hub drops entries of instances
	// started since).
	At time.Time
}

// Inputs is everything the checks judge (enabled instances only).
type Inputs struct {
	Now           time.Time
	BindRoots     []string
	Folders       []FolderIn
	Paths         []PathIn
	Ports         []PortIn
	Person        []PersonIn
	Changes       []ChangeIn
	LocalNetworks []netip.Prefix
	// Domain is the main domain, DomainAddrs its A / AAAA records;
	// DomainErr: the lookup failed (nothing escalates on it).
	Domain      string
	DomainAddrs []netip.Addr
	DomainErr   bool
	Scans       map[string]ScanIn // by cleaned host path
	Runtime     []RuntimeIn       // enabled instances' running containers (cached with the scans)
	// Unverifiable: active file-sharing credentials whose holder LLDAP
	// lists with an empty uuid — the holder check can't tell a re-created
	// account (contract §13.16, F31; plan 3 Task 11 raises the Problem
	// unverifiable_account "can't verify <user>'s account"). nil with the
	// directory unavailable.
	Unverifiable []UnverifiableIn
	// FileSharing: the file-sharing instances (filesharing.go).
	FileSharing []FileSharingIn
	// AI: the companions the AI checks judge (ai.go, plan 4 Task 20).
	AI []AIIn
}

// UnverifiableIn is one active credential the holder check can't verify
// (the holder's current LLDAP uuid is empty).
type UnverifiableIn struct {
	Instance string
	Key      string
	User     string
}

// Check is one kind of check.
type Check interface {
	Kind() string
	Run(in *Inputs) []Finding
}

var (
	regMu    sync.RWMutex
	registry []Check
)

// Register adds a check. The built-ins register in init(); later
// projects add their own. Several checks may share a kind (and a
// fingerprint: Run keeps the most severe).
func Register(c Check) {
	regMu.Lock()
	defer regMu.Unlock()
	registry = append(registry, c)
}

// checks is a copy of the registry.
func checks() []Check {
	regMu.RLock()
	defer regMu.RUnlock()
	return append([]Check(nil), registry...)
}

// Kinds is the check catalogue: every registered kind, sorted, once
// each (the Portcullis MCP's portcullis://doctor/checks resource).
func Kinds() []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range checks() {
		if k := c.Kind(); !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// Fingerprint is the first 16 hex digits of sha256(kind \x00 subjects
// sorted and joined by \x00): stable across runs and subject order.
func Fingerprint(kind string, subjects ...string) string {
	s := append([]string(nil), subjects...)
	sort.Strings(s)
	sum := sha256.Sum256([]byte(kind + "\x00" + strings.Join(s, "\x00")))
	return hex.EncodeToString(sum[:])[:16]
}

// Digest is the sha256 hex of v's canonical JSON (encoding/json sorts
// map keys).
func Digest(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		b = []byte(err.Error())
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Report is the doctor's answer.
type Report struct {
	Findings []Finding        `json:"findings"` // sorted: severity, title, fp
	Counts   map[Severity]int `json:"counts"`   // unmuted only
	Muted    int              `json:"muted"`
	Scans    []ScanSummary    `json:"scans"`
}

// ScanSummary is one cached disk scan.
type ScanSummary struct {
	Target  string    `json:"target"`
	At      time.Time `json:"at"`
	Partial bool      `json:"partial"`
	Entries int64     `json:"entries"`
}

// Run runs every registered check on in and applies mutes (by
// fingerprint, only while the inputs digest matches).
func Run(in *Inputs, mutes map[string]Mute) Report {
	byFP := map[string]Finding{}
	digests := map[string][]string{} // fp → every same-fp finding's digest
	for _, c := range checks() {
		for _, f := range c.Run(in) {
			if f.Kind == "" {
				f.Kind = c.Kind()
			}
			if f.FP == "" {
				f.FP = Fingerprint(f.Kind, f.Title)
			}
			f.Inputs = Digest([]string{string(f.Severity), f.Inputs})
			f.Muted = nil
			digests[f.FP] = append(digests[f.FP], f.Inputs)
			if old, ok := byFP[f.FP]; ok && old.Severity.rank() <= f.Severity.rank() {
				continue
			}
			byFP[f.FP] = f
		}
	}
	// Same-fp findings fold every digest into the kept one (H11 M3): new
	// evidence from a dropped one (runtime gid_collision under a static
	// one) lifts a mute too. A lone finding keeps its own.
	for fp, ds := range digests {
		if len(ds) > 1 {
			f := byFP[fp]
			sort.Strings(ds)
			f.Inputs = Digest(ds)
			byFP[fp] = f
		}
	}
	r := Report{Findings: make([]Finding, 0, len(byFP)), Counts: map[Severity]int{Problem: 0, Warning: 0, Info: 0}, Scans: []ScanSummary{}}
	for _, f := range byFP {
		f.Token = f.Inputs
		if m, ok := mutes[f.FP]; ok && m.Inputs == f.Inputs {
			m := m
			f.Muted = &m
			r.Muted++
		} else {
			r.Counts[f.Severity]++
		}
		r.Findings = append(r.Findings, f)
	}
	sort.Slice(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if a.Severity.rank() != b.Severity.rank() {
			return a.Severity.rank() < b.Severity.rank()
		}
		if a.Title != b.Title {
			return a.Title < b.Title
		}
		return a.FP < b.FP
	})
	for _, s := range in.Scans {
		sum := ScanSummary{Target: s.Target, At: s.At}
		if s.Report != nil {
			sum.Partial, sum.Entries = s.Report.Partial, s.Report.Entries
		}
		r.Scans = append(r.Scans, sum)
	}
	sort.Slice(r.Scans, func(i, j int) bool { return r.Scans[i].Target < r.Scans[j].Target })
	return r
}
