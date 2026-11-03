package templates

import (
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// Shared folders (template contract v3 MINOR, integration contracts
// §13.15): a path option's folder block, option-level doctor checks and
// LAN-only ports. Folder values (folder:<id>[/<subpath>]) are parsed by
// settings.ParseFolderRef; the folders themselves live in the Hub (§14).

// FolderSpec is a path option's folder block: what the app needs on a
// shared folder. It replaces mode, needs and writes_as.
type FolderSpec struct {
	Access     string  `yaml:"access" json:"access"` // FolderRead | FolderWrite
	RunsAs     *RunsAs `yaml:"runs_as" json:"runs_as"`
	JoinsGroup string  `yaml:"joins_group" json:"joins_group"` // "" = JoinGroupAdd
	MustOwn    bool    `yaml:"must_own" json:"must_own"`
}

// RunsAs is the uid and gid the app's process uses on the mount: each a
// number, or the env name of an instance int option (uid_env / gid_env).
// UIDFrom / GIDFrom are reserved (file sharing, project 3).
type RunsAs struct {
	UID     *int   `yaml:"uid" json:"uid,omitempty"`
	GID     *int   `yaml:"gid" json:"gid,omitempty"`
	UIDEnv  string `yaml:"uid_env" json:"uid_env,omitempty"`
	GIDEnv  string `yaml:"gid_env" json:"gid_env,omitempty"`
	UIDFrom string `yaml:"uid_from" json:"uid_from,omitempty"` // reserved: project 3
	GIDFrom string `yaml:"gid_from" json:"gid_from,omitempty"` // reserved: project 3
}

// Check is one template-declared doctor check (§13.15 catalog).
type Check struct {
	Kind   string   `yaml:"kind" json:"kind"`
	Reason string   `yaml:"reason" json:"reason"`
	Needs  []string `yaml:"needs" json:"needs,omitempty"` // filesystem: xattr, acl
	Not    []string `yaml:"not" json:"not,omitempty"`     // filesystem: nfs, cifs, fuse
	Min    string   `yaml:"min" json:"min,omitempty"`     // free_space: a size ("500GiB")
}

// Folder access, group joining and check kinds (§13.15).
const (
	FolderRead  = "read"
	FolderWrite = "write"

	JoinGroupAdd = "group_add"
	JoinGIDEnv   = "gid_env"
	JoinTemplate = "template"

	CheckFilesystem         = "filesystem"
	CheckExclusive          = "exclusive"
	CheckFreeSpace          = "free_space"
	CheckRequiresGroupValue = "requires_group_value"
	// CheckLANOnly is not an option check: it is the port flag
	// (Port.LanOnly) and the doctor's finding kind. A checks entry with
	// this kind is refused (preflight P2).
	CheckLANOnly = "lan_only"
)

// CheckKinds is the option-check catalog (lan_only is not in it).
var CheckKinds = map[string]bool{
	CheckFilesystem: true, CheckExclusive: true, CheckFreeSpace: true, CheckRequiresGroupValue: true,
}

// Folder gid range: the Hub allocates folder groups here (§14.1); no
// template may hard-code a gid in it.
const (
	FolderGIDMin = 60000
	FolderGIDMax = 60999
)

// InFolderGIDRange reports whether gid is a folder group's.
func InFolderGIDRange(gid int64) bool { return gid >= FolderGIDMin && gid <= FolderGIDMax }

// varFolderPrefix is the reserved prefix of the folder variables.
const varFolderPrefix = "PORTCULLIS_FOLDER_"

// FolderAccess is o's folder.access, or "" without a folder block.
func (o *Option) FolderAccess() string {
	if o.Folder == nil {
		return ""
	}
	return o.Folder.Access
}

// Join is how the app joins the folder's group (JoinGroupAdd by default).
func (f *FolderSpec) Join() string {
	if f.JoinsGroup == "" {
		return JoinGroupAdd
	}
	return f.JoinsGroup
}

// FolderGIDVar is the env variable carrying option key's folder gid.
func FolderGIDVar(key string) string { return varFolderPrefix + "GID_" + strings.ToUpper(key) }

// FolderUIDVar is the env variable carrying option key's must_own uid.
func FolderUIDVar(key string) string { return varFolderPrefix + "UID_" + strings.ToUpper(key) }

// ── validation (§13.15) ──────────────────────────────────

// maxRunsAsID bounds a runs_as uid / gid.
const maxRunsAsID = 1<<31 - 1

// checkReasonMax bounds a check's reason (characters).
const checkReasonMax = 200

// gidRangeText is the refusal's wording of the folder gid range.
var gidRangeText = fmt.Sprintf("%d-%d (shared folder groups)", FolderGIDMin, FolderGIDMax)

// folderOption checks o's folder block (contract §13.15).
func (v *specCheck) folderOption(o *Option) error {
	f := o.Folder
	if f == nil {
		return nil
	}
	if o.Type != TypePath || o.EffectiveScope() != ScopeInstance {
		return fmt.Errorf("folder is for path options with scope instance (not type %s, scope %s)", o.Type, o.EffectiveScope())
	}
	for _, r := range []struct {
		name string
		on   bool
	}{{"mode", o.Mode != ""}, {"needs", o.Needs != ""}, {"writes_as", o.WritesAs != nil}} {
		if r.on {
			return fmt.Errorf("%s together with folder: folder.access and folder.runs_as replace them", r.name)
		}
	}
	switch f.Access {
	case FolderRead, FolderWrite:
	case "":
		return fmt.Errorf("folder.access is required (read or write)")
	default:
		return fmt.Errorf("folder.access %q must be read or write", f.Access)
	}
	ra := f.RunsAs
	if ra == nil {
		return fmt.Errorf("folder.runs_as is required (the uid and gid the app uses on the mount)")
	}
	for _, id := range []struct {
		what string
		num  *int
		env  string
	}{{"uid", ra.UID, ra.UIDEnv}, {"gid", ra.GID, ra.GIDEnv}} {
		if (id.num != nil) == (id.env != "") {
			return fmt.Errorf("folder.runs_as.%s: exactly one of %s, %s_env (a number, or the env name of an instance int option)", id.what, id.what, id.what)
		}
		if id.num != nil {
			if *id.num < 0 || *id.num > maxRunsAsID {
				return fmt.Errorf("folder.runs_as.%s %d is not a valid id (0-%d)", id.what, *id.num, maxRunsAsID)
			}
			if id.what == "gid" && InFolderGIDRange(int64(*id.num)) {
				return fmt.Errorf("folder.runs_as.gid %d is in %s", *id.num, gidRangeText)
			}
			continue
		}
		if ReservedVar(id.env) || strings.HasPrefix(id.env, "PORTCULLIS_") {
			return fmt.Errorf("folder.runs_as.%s_env %s is reserved (PORTCULLIS_*: core and the Hub set them)", id.what, id.env)
		}
		ro := v.envOption(id.env)
		if ro == nil {
			return fmt.Errorf("folder.runs_as.%s_env %s is not the env name of an instance int option of this template", id.what, id.env)
		}
		if d, ok := defaultInt(ro.Default); ok && InFolderGIDRange(d) {
			return fmt.Errorf("folder.runs_as.%s_env %s names setting %s, whose default %d is in %s", id.what, id.env, ro.Key, d, gidRangeText)
		}
	}
	switch f.JoinsGroup {
	case "", JoinGroupAdd, JoinTemplate:
	case JoinGIDEnv:
		if ra.GIDEnv == "" {
			return fmt.Errorf("folder.joins_group: gid_env needs runs_as.gid_env (the variable the folder gid is written to)")
		}
	default:
		return fmt.Errorf("folder.joins_group %q must be group_add, gid_env or template", f.JoinsGroup)
	}
	if f.MustOwn && f.Access != FolderWrite {
		return fmt.Errorf("folder.must_own needs access: write (the Hub makes the app the owner of what it writes)")
	}
	if o.Target == nil {
		return nil // pathAndSecret refuses it
	}
	if err := v.composeUserMatches(o.Target.Service, ra); err != nil {
		return err
	}
	return v.sameEnvSameRunsAs(o)
}

// envOption is the instance int option whose EnvName() is name.
func (v *specCheck) envOption(name string) *Option {
	for i := range v.m.Settings.Options {
		ro := &v.m.Settings.Options[i]
		if ro.Type == TypeInt && ro.EffectiveScope() == ScopeInstance && ro.EnvName() == name {
			return ro
		}
	}
	return nil
}

// defaultInt reads a manifest default as an integer.
func defaultInt(d any) (int64, bool) {
	switch x := d.(type) {
	case int:
		return int64(x), true
	case int64:
		return x, true
	case uint64:
		if x > 1<<62 {
			return 0, false
		}
		return int64(x), true
	}
	return 0, false
}

// sameEnvSameRunsAs: folder options of one service that share a uid_env
// or gid_env must agree on runs_as and joins_group (one primary gid per
// process).
func (v *specCheck) sameEnvSameRunsAs(o *Option) error {
	ra := o.Folder.RunsAs
	for i := range v.m.Settings.Options {
		p := &v.m.Settings.Options[i]
		if p == o || p.Key == o.Key {
			break
		}
		if p.Folder == nil || p.Folder.RunsAs == nil || p.Target == nil || p.Target.Service != o.Target.Service {
			continue
		}
		pr := p.Folder.RunsAs
		var shared string
		switch {
		case ra.GIDEnv != "" && ra.GIDEnv == pr.GIDEnv:
			shared = "gid_env " + ra.GIDEnv
		case ra.UIDEnv != "" && ra.UIDEnv == pr.UIDEnv:
			shared = "uid_env " + ra.UIDEnv
		default:
			continue
		}
		if !reflect.DeepEqual(*ra, *pr) || o.Folder.Join() != p.Folder.Join() {
			return fmt.Errorf("folder names %s like setting %s on service %s, with another runs_as or joins_group (one primary gid per process: use identical blocks)", shared, p.Key, o.Target.Service)
		}
	}
	return nil
}

// userPart is one id of a compose user: value.
type userPart struct {
	num   *int64 // a literal number
	env   string // ${NAME…} / $NAME
	other bool   // a name (www-data) or anything else
}

var (
	userEnvRe  = regexp.MustCompile(`^\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?-[^}]*)?\}$`)
	userBareRe = regexp.MustCompile(`^\$([A-Za-z_][A-Za-z0-9_]*)$`)
	userNumRe  = regexp.MustCompile(`^[0-9]{1,10}$`)
)

func parseUserPart(s string) userPart {
	if userNumRe.MatchString(s) {
		n, _ := strconv.ParseInt(s, 10, 64)
		return userPart{num: &n}
	}
	if m := userEnvRe.FindStringSubmatch(s); m != nil {
		return userPart{env: m[1]}
	}
	if m := userBareRe.FindStringSubmatch(s); m != nil {
		return userPart{env: m[1]}
	}
	return userPart{other: true}
}

// splitUser splits a compose user: at the first ':' outside ${…}.
func splitUser(u string) (uid, gid string, hasGID bool) {
	depth := 0
	for i := 0; i < len(u); i++ {
		switch {
		case u[i] == '$' && i+1 < len(u) && u[i+1] == '{':
			depth++
			i++
		case u[i] == '}' && depth > 0:
			depth--
		case u[i] == ':' && depth == 0:
			return u[:i], u[i+1:], true
		}
	}
	return u, "", false
}

// composeUsers reads every service's user: ("" = not set).
func composeUsers(compose []byte) map[string]string {
	var doc struct {
		Services map[string]struct {
			User yaml.Node `yaml:"user"`
		} `yaml:"services"`
	}
	out := map[string]string{}
	if yaml.Unmarshal(compose, &doc) != nil {
		return out
	}
	for svc, s := range doc.Services {
		if s.User.Kind == yaml.ScalarNode && s.User.Tag != "!!null" {
			out[svc] = s.User.Value
		}
	}
	return out
}

// composeUserGIDs refuses a compose user: gid in the folder gid range on
// any service.
func (v *specCheck) composeUserGIDs() error {
	svcs := make([]string, 0, len(v.users))
	for s := range v.users {
		svcs = append(svcs, s)
	}
	sort.Strings(svcs)
	for _, s := range svcs {
		if _, g, ok := splitUser(v.users[s]); ok {
			if p := parseUserPart(g); p.num != nil && InFolderGIDRange(*p.num) {
				return fmt.Errorf("service %s: compose user: gid %d is in %s", s, *p.num, gidRangeText)
			}
		}
	}
	return nil
}

// composeUserMatches checks runs_as against service svc's compose user:.
func (v *specCheck) composeUserMatches(svc string, ra *RunsAs) error {
	u := v.users[svc]
	if u == "" {
		return nil
	}
	us, gs, hasGID := splitUser(u)
	ids := []struct {
		what string
		part userPart
		num  *int
		env  string
	}{{"uid", parseUserPart(us), ra.UID, ra.UIDEnv}}
	if hasGID {
		ids = append(ids, struct {
			what string
			part userPart
			num  *int
			env  string
		}{"gid", parseUserPart(gs), ra.GID, ra.GIDEnv})
	}
	for _, id := range ids {
		p := id.part
		switch {
		case p.other:
			return fmt.Errorf("service %s's compose user: %q is not numeric next to a folder block: give numbers in compose `user:` (uid:gid, or ${PUID:-1000}:${PGID:-1000})", svc, u)
		case p.num != nil && id.num != nil:
			if int64(*id.num) != *p.num {
				return fmt.Errorf("folder.runs_as.%s %d doesn't match service %s's compose user: %q", id.what, *id.num, svc, u)
			}
		case p.num != nil:
			return fmt.Errorf("folder.runs_as.%s_env %s doesn't match service %s's compose user: %q (use %s: %d)", id.what, id.env, svc, u, id.what, *p.num)
		case id.num != nil:
			return fmt.Errorf("folder.runs_as.%s: service %s's compose user: takes it from ${%s}: use %s_env: %s", id.what, svc, p.env, id.what, p.env)
		case id.env != p.env:
			return fmt.Errorf("folder.runs_as.%s_env %s doesn't match service %s's compose user: %q (use %s_env: %s)", id.what, id.env, svc, u, id.what, p.env)
		}
	}
	return nil
}

// checkParams are the parameters each check kind takes.
var checkParams = map[string]map[string]bool{
	CheckFilesystem: {"needs": true, "not": true},
	CheckFreeSpace:  {"min": true},
}

var (
	fsNeeds = map[string]bool{"xattr": true, "acl": true}
	fsNot   = map[string]bool{"nfs": true, "cifs": true, "fuse": true}
)

// checks validates o's checks against the catalog (§13.15). free_space's
// min is parsed by settings.Registry.CheckOption (binary units only).
func (v *specCheck) checks(o *Option) error {
	seen := map[string]bool{}
	for i, c := range o.Checks {
		if c.Kind == CheckLANOnly {
			return fmt.Errorf("checks[%d]: kind lan_only is not an option check: set lan_only: true on the port", i)
		}
		if !CheckKinds[c.Kind] {
			return fmt.Errorf("checks[%d]: unknown kind %q (the catalog: %s)", i, c.Kind, strings.Join(sortedCheckKinds(), ", "))
		}
		w := fmt.Sprintf("checks[%d] (%s)", i, c.Kind)
		if seen[c.Kind] {
			return fmt.Errorf("%s: listed twice", w)
		}
		seen[c.Kind] = true
		if strings.TrimSpace(c.Reason) == "" || utf8.RuneCountInString(c.Reason) > checkReasonMax || HasControlChars(c.Reason) {
			return fmt.Errorf("%s: reason must be one line of 1-%d characters, without control characters", w, checkReasonMax)
		}
		switch c.Kind {
		case CheckFilesystem:
			if o.Type != TypePath || o.Folder == nil {
				return fmt.Errorf("%s: needs a path option with a folder block", w)
			}
		case CheckExclusive:
			if o.Type != TypePath || o.FolderAccess() != FolderWrite {
				return fmt.Errorf("%s: needs a path option with folder.access: write", w)
			}
		case CheckFreeSpace:
			if o.Type != TypePath {
				return fmt.Errorf("%s: needs a path option", w)
			}
		case CheckRequiresGroupValue:
			if o.EffectiveScope() != ScopePerson {
				return fmt.Errorf("%s: needs scope: person", w)
			}
		}
		for _, p := range []struct {
			name string
			on   bool
		}{{"needs", c.Needs != nil}, {"not", c.Not != nil}, {"min", c.Min != ""}} {
			if p.on && !checkParams[c.Kind][p.name] {
				return fmt.Errorf("%s: %s takes no %s", w, c.Kind, p.name)
			}
		}
		switch c.Kind {
		case CheckFilesystem:
			if len(c.Needs) == 0 && len(c.Not) == 0 {
				return fmt.Errorf("%s: filesystem needs needs or not (what to check)", w)
			}
			if err := checkSubset(w, "needs", c.Needs, fsNeeds, "xattr or acl"); err != nil {
				return err
			}
			if err := checkSubset(w, "not", c.Not, fsNot, "nfs, cifs or fuse"); err != nil {
				return err
			}
		case CheckFreeSpace:
			if c.Min == "" {
				return fmt.Errorf("%s: free_space needs min (a size such as 500GiB)", w)
			}
		}
	}
	return nil
}

func checkSubset(w, field string, l []string, allowed map[string]bool, want string) error {
	seen := map[string]bool{}
	for _, x := range l {
		if !allowed[x] {
			return fmt.Errorf("%s: %s %q must be %s", w, field, x, want)
		}
		if seen[x] {
			return fmt.Errorf("%s: %s %q listed twice", w, field, x)
		}
		seen[x] = true
	}
	return nil
}

func sortedCheckKinds() []string {
	out := make([]string, 0, len(CheckKinds))
	for k := range CheckKinds {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
