package doctor

import (
	"fmt"
	"path"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/portcullis/hub/internal/settings"
)

// File-sharing checks (contract §14.5 "File sharing (NEW)", §13.16–13.17;
// plan 3 Task 11). They judge what the Hub gathers per file-sharing
// instance (Inputs.FileSharing): the holder check's verdict on each active
// credential (the canary), the per-person trees' top-level directories
// (from their disk scans or the app's hook report), the last hook report's
// findings, an empty Local networks list, share slots served to nobody,
// and the credentials whose holder can't be verified (Inputs.Unverifiable).

// HolderIn is one active credential of a file-sharing instance: Key the
// person_secret option, HasAccess false when the holder check (the Hub's
// credentialRevocations, F56) would revoke it.
type HolderIn struct {
	Key, User string
	HasAccess bool
}

// TreeIn is a per-person tree (a gid_from path option with a host path):
// People maps each person of the population who has an id to the uid
// (and gid) their top-level directory must have; nil = unknown (the
// directory is unavailable: the tree isn't judged).
type TreeIn struct {
	Instance, Key, Label, HostPath string
	People                         map[string]int
}

// UnservedIn is an option with a value whose requires_any options are all
// unset (a share slot with a folder but neither readers nor writers).
type UnservedIn struct {
	Key, Label     string
	Requires       []string // the requires_any keys
	RequiresLabels []string
}

// FileSharingIn is one file-sharing instance (person_secret, person_id,
// per-person trees, PORTCULLIS_LOCAL_NETWORKS or a hook report). Label is
// the app's name as findings show it.
type FileSharingIn struct {
	Instance, Label string
	Holders         []HolderIn           // active credentials (nil: the directory is unavailable)
	Trees           []TreeIn             // gid_from path options with a value
	Report          *settings.HookReport // last accepted hook report, may be nil
	ReportAt        time.Time            // when it arrived
	// LocalNetworksEmpty: Local networks is saved empty while this
	// enabled instance's compose references PORTCULLIS_LOCAL_NETWORKS.
	LocalNetworksEmpty bool
	Unserved           []UnservedIn
}

// Kinds and fixes of this file.
const (
	KindCredentialWithoutAccess = "credential_without_access"
	KindFormerAccountFolder     = "former_account_folder"
	KindPersonTreeOwner         = "person_tree_owner"
	KindLocalNetworksEmpty      = "local_networks_empty"
	KindUnverifiableAccount     = "unverifiable_account"
	KindServedToNobody          = "served_to_nobody"
	// The hook report's own findings (kind = the report's code).
	KindNameRefused     = "name_refused"
	KindOwnerUnwritable = "owner_unwritable"

	FixRevokeLeaver    = "revoke_leaver"
	FixPersonTreeOwner = "person_tree_owner"
)

// The hook report's codes (contract §13.8).
const (
	codeFormerAccount   = "former_account"
	codeWrongOwner      = "wrong_owner"
	codeNameRefused     = "name_refused"
	codeOwnerUnwritable = "owner_unwritable"
)

func init() {
	Register(credentialCanaryCheck{})
	// One check per kind (each a filter of the same judgement).
	Register(personTreeCheck{KindPersonTreeOwner})
	Register(personTreeCheck{KindFormerAccountFolder})
	Register(hookReportCheck{KindNameRefused})
	Register(hookReportCheck{KindOwnerUnwritable})
	Register(localNetworksEmptyCheck{})
	Register(unverifiableCheck{})
	Register(servedToNobodyCheck{})
}

// CredentialFP is credential_without_access's fingerprint for a holder.
func CredentialFP(instance, key, user string) string {
	return Fingerprint(KindCredentialWithoutAccess, "instance:"+instance, "key:"+key, "user:"+user)
}

// TreeFP is the fingerprint of a person's top-level directory finding of
// kind (former_account_folder, person_tree_owner): the same from a tree
// scan and from the hook report.
func TreeFP(kind, instance, key, user string) string {
	return Fingerprint(kind, "instance:"+instance, "key:"+key, "user:"+user)
}

// reportText is untrusted report text as findings show it: valid UTF-8,
// graphic characters only (controls and format characters such as bidi
// overrides become U+FFFD), one line, at most 200 characters. The UI
// escapes it again.
func reportText(s string) string {
	s = strings.ToValidUTF8(s, "�")
	s = strings.Map(func(r rune) rune {
		if r == ' ' || (unicode.IsGraphic(r) && !unicode.Is(unicode.Cf, r)) {
			return r
		}
		return '�'
	}, s)
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > 200 {
		s = string([]rune(s)[:199]) + "…"
	}
	return s
}

func sortedFileSharing(in *Inputs) []FileSharingIn {
	fs := slices.Clone(in.FileSharing)
	sort.Slice(fs, func(i, j int) bool { return fs[i].Instance < fs[j].Instance })
	return fs
}

func labelOf(fs FileSharingIn) string {
	if fs.Label != "" {
		return fs.Label
	}
	return fs.Instance
}

// ── credential_without_access (the canary) ──────────────

type credentialCanaryCheck struct{}

func (credentialCanaryCheck) Kind() string { return KindCredentialWithoutAccess }

func (credentialCanaryCheck) Run(in *Inputs) []Finding {
	var out []Finding
	for _, fs := range sortedFileSharing(in) {
		app := labelOf(fs)
		for _, h := range fs.Holders {
			if h.HasAccess {
				continue
			}
			out = append(out, Finding{
				FP: CredentialFP(fs.Instance, h.Key, h.User), Kind: KindCredentialWithoutAccess, Severity: Problem,
				Title: fmt.Sprintf("%s still has a file-share password for %s without access to it.", h.User, app),
				Why: fmt.Sprintf("The Hub revokes a file-share password as soon as its holder loses access; %s's for %s wasn't revoked (a revocation that failed?), so it may still work.",
					h.User, app),
				Fix:       fmt.Sprintf("Revoke %s's file-share password for %s now (the admin revoke: the password stops working, its sessions end).", h.User, app),
				Instances: []string{fs.Instance},
				Class:     FixOneClick, FixKind: FixRevokeLeaver,
				Inputs: Digest([]string{fs.Instance, h.Key, h.User}),
			})
		}
	}
	return out
}

// ── per-person trees ─────────────────────────────────────

// personTreeCheck reports kind's findings of the per-person trees
// (person_tree_owner, former_account_folder).
type personTreeCheck struct{ kind string }

func (c personTreeCheck) Kind() string { return c.kind }

// treeScan is the tree's cached top-level scan (ok false: none).
func treeScan(in *Inputs, t TreeIn) (ScanIn, bool) {
	s, ok := in.Scans[path.Clean(t.HostPath)]
	if !ok || !s.Tree || s.Report == nil || s.Report.Children == nil {
		return ScanIn{}, false
	}
	return s, true
}

func (c personTreeCheck) Run(in *Inputs) []Finding {
	return slices.DeleteFunc(judgeTrees(in), func(f Finding) bool { return f.Kind != c.kind })
}

func judgeTrees(in *Inputs) []Finding {
	var out []Finding
	for _, fs := range sortedFileSharing(in) {
		app := labelOf(fs)
		trees := slices.Clone(fs.Trees)
		sort.Slice(trees, func(i, j int) bool { return trees[i].Key < trees[j].Key })
		for _, t := range trees {
			if t.People == nil {
				continue
			}
			s, scanned := treeScan(in, t)
			// The newer source wins: a scan after the report (after a
			// one-click fix, say) or the report after the scan.
			if scanned && (fs.Report == nil || !s.At.Before(fs.ReportAt)) {
				out = append(out, treeFromScan(fs, app, t, s)...)
				continue
			}
			out = append(out, treeFromReport(fs, app, t, len(trees) == 1, s, scanned)...)
		}
	}
	return out
}

func formerFinding(fs FileSharingIn, app string, t TreeIn, user string, uid int64) Finding {
	p := path.Join(t.HostPath, user)
	return Finding{
		FP: TreeFP(KindFormerAccountFolder, fs.Instance, t.Key, user), Kind: KindFormerAccountFolder, Severity: Warning,
		Title: fmt.Sprintf("%s's %s folder belongs to a former account (uid %d).", user, app, uid),
		Why: fmt.Sprintf("`%s` is owned by uid %d, not %s's: most likely a deleted account whose name was created again. The app doesn't serve it, so the former account's files stay private, and %s can't use that folder until it is moved.",
			p, uid, user, user),
		Class: FixExplain,
		Steps: []string{
			fmt.Sprintf("Decide what happens to the former account's files in `%s`: move them elsewhere (or delete them) by hand. The Hub never moves or deletes data.", p),
			"Run the doctor's disk check again: once the folder is gone the app creates a new one for " + user + ".",
		},
		Instances: []string{fs.Instance}, Paths: []string{p},
		Inputs: Digest([]any{p, uid}),
	}
}

func ownerFinding(fs FileSharingIn, app string, t TreeIn, user string, uid int, now string) Finding {
	p := path.Join(t.HostPath, user)
	return Finding{
		FP: TreeFP(KindPersonTreeOwner, fs.Instance, t.Key, user), Kind: KindPersonTreeOwner, Severity: Warning,
		Title: fmt.Sprintf("%s's %s folder has the wrong group or mode.", user, app),
		Why: fmt.Sprintf("`%s` belongs to %s (uid %d) but %s: a person's folder must be %d:%d with mode 0700, so nobody else can read it.",
			p, user, uid, now, uid, uid),
		Fix:   fmt.Sprintf("chown %d:%d + chmod 0700 %s (not recursive: nothing inside it changes).", uid, uid, p),
		Class: FixOneClick, FixKind: FixPersonTreeOwner,
		Instances: []string{fs.Instance}, Paths: []string{p},
		Inputs: Digest([]any{p, uid, now}),
	}
}

func treeFromScan(fs FileSharingIn, app string, t TreeIn, s ScanIn) []Finding {
	var out, infos []Finding
	var others []string
	for _, c := range s.Report.Children {
		uid, person := t.People[c.Name]
		switch {
		case !person || !c.Dir:
			others = append(others, c.Name)
		case c.UID != uid:
			out = append(out, formerFinding(fs, app, t, c.Name, int64(c.UID)))
		case c.GID != uid || c.Mode != 0o700:
			out = append(out, ownerFinding(fs, app, t, c.Name, uid, fmt.Sprintf("has group %d and mode %04o", c.GID, c.Mode)))
		}
	}
	if len(others) > 0 {
		sort.Strings(others)
		shown := others[:min(len(others), 5)]
		more := ""
		if len(others) > len(shown) {
			more = fmt.Sprintf(" and %d more", len(others)-len(shown))
		}
		infos = append(infos, Finding{
			FP: Fingerprint(KindPersonTreeOwner, "instance:"+fs.Instance, "key:"+t.Key, "others"), Kind: KindPersonTreeOwner, Severity: Info,
			Title: fmt.Sprintf("%s: %d %s at the top of `%s` %s no current person's folder.", app, len(others),
				plural(int64(len(others)), "entry", "entries"), t.HostPath, plural(int64(len(others)), "is", "are")),
			Why: fmt.Sprintf("Only people with access have a folder there: %s%s. Former members' folders stay on disk until you move or delete them.",
				joinAnd(quoted(shown)), more),
			Instances: []string{fs.Instance}, Paths: []string{t.HostPath},
			Inputs: Digest(others),
		})
	}
	for i := range out {
		partial(&out[i], s)
	}
	return append(out, infos...)
}

// treeFromReport: the hook report's former_account and wrong_owner
// findings about tree t (their option is t's key; with a single tree, a
// finding without an option is t's too). A wrong_owner offers the
// one-click fix only when the tree's scan s (older than the report) shows
// the person's own uid owning the directory (fix round 1: the fix never
// takes a folder from another owner); else it is explain-only.
func treeFromReport(fs FileSharingIn, app string, t TreeIn, only bool, s ScanIn, scanned bool) []Finding {
	if fs.Report == nil {
		return nil
	}
	var out []Finding
	for _, f := range fs.Report.Findings {
		if f.Option != t.Key && (f.Option != "" || !only) {
			continue
		}
		uid, person := t.People[f.Subject]
		if !person {
			continue
		}
		switch f.Code {
		case codeFormerAccount:
			owner := int64(-1)
			if f.UID != nil {
				owner = *f.UID
			}
			if owner == int64(uid) {
				continue
			}
			out = append(out, formerFinding(fs, app, t, f.Subject, owner))
		case codeWrongOwner:
			subj := f.Subject
			wf := ownerFinding(fs, app, t, subj, uid, "the app reports another group or mode")
			own := false
			if scanned {
				for _, c := range s.Report.Children {
					own = own || (c.Name == subj && c.Dir && c.UID == uid)
				}
			}
			if !own {
				wf.Class, wf.FixKind, wf.Fix = FixExplain, "", ""
				wf.Why = fmt.Sprintf("%s reports that `%s` doesn't have the owner, group or mode a person's folder needs (%d:%d, mode 0700); no disk check has shown it owned by %s's uid yet.",
					app, path.Join(t.HostPath, subj), uid, uid, subj)
				wf.Steps = []string{"Run the disk check (Doctor → Check disks): the one-click fix is offered once the check shows the folder is owned by the person's own uid; a folder of another uid is a former account's, moved by hand."}
			}
			out = append(out, wf)
		}
	}
	return out
}

// ── the hook report's own findings ───────────────────────

// hookReportCheck reports the hook report's findings of one code
// (name_refused, owner_unwritable) with their severity and text.
type hookReportCheck struct{ code string }

func (c hookReportCheck) Kind() string { return c.code }

func (c hookReportCheck) Run(in *Inputs) []Finding {
	var out []Finding
	for _, fs := range sortedFileSharing(in) {
		if fs.Report == nil {
			continue
		}
		app := labelOf(fs)
		for _, f := range fs.Report.Findings {
			if f.Code != c.code {
				continue
			}
			var steps []string
			switch f.Code {
			case codeNameRefused:
				steps = []string{"Pick another name in the app's settings: the app refuses names it reserves and names another of its shares already has."}
			case codeOwnerUnwritable:
				steps = []string{"Check the folder's owner and permissions on the host (and the app's settings), then run the doctor again."}
			default:
				continue // former_account / wrong_owner: the tree kinds
			}
			sev := Severity(f.Severity)
			if sev.rank() > 2 {
				sev = Info
			}
			subject, msg := reportText(f.Subject), reportText(f.Message)
			if msg == "" {
				msg = f.Code + ": " + subject
			}
			out = append(out, Finding{
				FP:       Fingerprint(f.Code, "instance:"+fs.Instance, "subject:"+f.Subject, "option:"+f.Option),
				Kind:     f.Code,
				Severity: sev,
				Title:    fmt.Sprintf("%s reports: %s", app, msg),
				Why:      fmt.Sprintf("%s's own check (its hook report) says so about %q.", app, subject),
				Class:    FixExplain, Steps: steps,
				Instances: []string{fs.Instance},
				Inputs:    Digest([]string{f.Severity, f.Message}),
			})
		}
	}
	return out
}

// ── local_networks_empty ─────────────────────────────────

type localNetworksEmptyCheck struct{}

func (localNetworksEmptyCheck) Kind() string { return KindLocalNetworksEmpty }

func (localNetworksEmptyCheck) Run(in *Inputs) []Finding {
	var insts []string
	for _, fs := range sortedFileSharing(in) {
		if fs.LocalNetworksEmpty {
			insts = append(insts, fs.Instance)
		}
	}
	if len(insts) == 0 {
		return nil
	}
	return []Finding{{
		FP: Fingerprint(KindLocalNetworksEmpty), Kind: KindLocalNetworksEmpty, Severity: Problem,
		Title:     "Local networks is empty; file sharing is off.",
		Why:       fmt.Sprintf("Local networks is saved empty (loopback only), so %s %s nobody on the LAN: a file-sharing app never allows everyone instead.", joinAnd(insts), plural(int64(len(insts)), "lets", "let")),
		Class:     FixExplain,
		Steps:     []string{"Open Settings → Local networks and add your LAN's networks (or go back to the defaults); the apps restart with the new list."},
		Instances: insts,
		Inputs:    Digest(insts),
	}}
}

// ── unverifiable_account ─────────────────────────────────

type unverifiableCheck struct{}

func (unverifiableCheck) Kind() string { return KindUnverifiableAccount }

func (unverifiableCheck) Run(in *Inputs) []Finding {
	labels := map[string]string{}
	for _, fs := range in.FileSharing {
		labels[fs.Instance] = labelOf(fs)
	}
	us := slices.Clone(in.Unverifiable)
	sort.Slice(us, func(i, j int) bool {
		a, b := us[i], us[j]
		if a.Instance != b.Instance {
			return a.Instance < b.Instance
		}
		if a.Key != b.Key {
			return a.Key < b.Key
		}
		return a.User < b.User
	})
	var out []Finding
	for _, u := range us {
		app := labels[u.Instance]
		if app == "" {
			app = u.Instance
		}
		out = append(out, Finding{
			FP: Fingerprint(KindUnverifiableAccount, "instance:"+u.Instance, "key:"+u.Key, "user:"+u.User), Kind: KindUnverifiableAccount, Severity: Problem,
			Title: fmt.Sprintf("%s: can't verify %s's account.", app, u.User),
			Why: fmt.Sprintf("LLDAP lists %s without a uuid, so the Hub can't tell whether the account that holds this file-share password was deleted and created again; the password stays until it can.",
				u.User),
			Class: FixExplain,
			Steps: []string{
				"Check " + u.User + " in LLDAP: an account always has a uuid; a missing one points at a damaged or hand-edited directory.",
				"If the account was deleted and created again, revoke " + u.User + "'s password in the app's File sharing tab.",
			},
			Instances: []string{u.Instance},
			Inputs:    Digest([]string{u.Instance, u.Key, u.User}),
		})
	}
	return out
}

// ── served_to_nobody ─────────────────────────────────────

type servedToNobodyCheck struct{}

func (servedToNobodyCheck) Kind() string { return KindServedToNobody }

func (servedToNobodyCheck) Run(in *Inputs) []Finding {
	var out []Finding
	for _, fs := range sortedFileSharing(in) {
		app := labelOf(fs)
		for _, u := range fs.Unserved {
			label := u.Label
			if label == "" {
				label = u.Key
			}
			link := ""
			if len(u.Requires) > 0 {
				link = u.Requires[0]
			}
			out = append(out, Finding{
				FP: Fingerprint(KindServedToNobody, "instance:"+fs.Instance, "key:"+u.Key), Kind: KindServedToNobody, Severity: Warning,
				Title: fmt.Sprintf("%s of %s is served to nobody.", label, app),
				Why:   fmt.Sprintf("%s is set, but none of %s is: the app serves it to nobody.", label, joinAnd(u.RequiresLabels)),
				Fix:   fmt.Sprintf("Open the setting and pick who may use it (%s), or clear %s.", strings.Join(u.RequiresLabels, " / "), label),
				Class: FixLink, Link: &Link{Instance: fs.Instance, Option: link},
				Instances: []string{fs.Instance},
				Inputs:    Digest([]string{u.Key}),
			})
		}
	}
	return out
}
