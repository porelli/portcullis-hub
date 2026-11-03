package templates

import (
	"fmt"
	"math"
	"reflect"
	"regexp"
	"slices"
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

// UnmarshalYAML decodes strictly, with a friendly refusal for a uid / gid
// that isn't a whole number.
func (r *RunsAs) UnmarshalYAML(n *yaml.Node) error {
	var p struct {
		UID     yaml.Node `yaml:"uid"`
		GID     yaml.Node `yaml:"gid"`
		UIDEnv  string    `yaml:"uid_env"`
		GIDEnv  string    `yaml:"gid_env"`
		UIDFrom string    `yaml:"uid_from"`
		GIDFrom string    `yaml:"gid_from"`
	}
	if err := strictDecode(n, &p); err != nil {
		return err
	}
	num := func(what string, nd *yaml.Node) (*int, error) {
		if nd.Kind == 0 || nd.Tag == "!!null" {
			return nil, nil
		}
		var v int
		if nd.Kind != yaml.ScalarNode || nd.Tag != "!!int" || nd.Decode(&v) != nil {
			return nil, fmt.Errorf("folder.runs_as.%s: want a whole number, not %q (a variable goes in %s_env)", what, nd.Value, what)
		}
		return &v, nil
	}
	var err error
	if r.UID, err = num("uid", &p.UID); err != nil {
		return err
	}
	if r.GID, err = num("gid", &p.GID); err != nil {
		return err
	}
	r.UIDEnv, r.GIDEnv, r.UIDFrom, r.GIDFrom = p.UIDEnv, p.GIDEnv, p.UIDFrom, p.GIDFrom
	return nil
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
		switch d, bad, in := idDefault(ro); {
		case bad:
			return fmt.Errorf("folder.runs_as.%s_env %s names setting %s, whose default %s is not a whole number", id.what, id.env, ro.Key, quoteDefault(ro.Default))
		case in && id.what == "gid":
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
	if err := v.groupAddResolves(o.Target.Service); err != nil {
		return err
	}
	return v.sameEnvSameRunsAs(o)
}

// envOption is the instance int option that delivers env name.
// Every env name the option delivers counts (EnvNames: later and indexed
// deliveries too).
func (v *specCheck) envOption(name string) *Option {
	if ro := v.anyEnvOption(name); ro != nil && ro.Type == TypeInt {
		return ro
	}
	return nil
}

// defaultInt reads a manifest default as an integer: a YAML int, a whole
// float, or a decimal string (an int option parses one; review I1).
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
	case float64:
		if x != math.Trunc(x) || math.Abs(x) > 1<<53 {
			return 0, false
		}
		return int64(x), true
	case string:
		if !decimalRe.MatchString(x) {
			return 0, false
		}
		n, err := strconv.ParseInt(x, 10, 64)
		return n, err == nil
	}
	return 0, false
}

var decimalRe = regexp.MustCompile(`^-?[0-9]{1,18}$`)

// idDefault checks the default of option ro, which an id (runs_as env,
// writes_as key, compose reference) refers to: readable as a whole number
// when set (bad) and in the folder gid range (inRange, the value).
func idDefault(ro *Option) (d int64, bad, inRange bool) {
	if ro.Default == nil {
		return 0, false, false
	}
	d, ok := defaultInt(ro.Default)
	if !ok {
		return 0, true, false
	}
	return d, false, InFolderGIDRange(d)
}

func quoteDefault(d any) string {
	if s, ok := d.(string); ok {
		return strconv.Quote(s)
	}
	return fmt.Sprint(d)
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
		for _, j := range []*Option{p, o} {
			if j.Folder.Join() == JoinGIDEnv && ra.GIDEnv != pr.GIDEnv {
				other := o
				if j == o {
					other = p
				}
				return fmt.Errorf("service %s joins a folder group through gid_env %s: every folder option on it must use runs_as.gid_env %s (setting %s doesn't)", o.Target.Service, j.Folder.RunsAs.GIDEnv, j.Folder.RunsAs.GIDEnv, other.Key)
			}
		}
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
	userNumRe = regexp.MustCompile(`^[0-9]{1,10}$`)
)

func parseUserPart(s string) userPart {
	if userNumRe.MatchString(s) {
		n, _ := strconv.ParseInt(s, 10, 64)
		return userPart{num: &n}
	}
	if m := singleRefRe.FindStringSubmatch(s); m != nil {
		if m[1] != "" {
			return userPart{env: m[1]}
		}
		return userPart{env: m[4]}
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

// composeIDs reads every service's user: ("" = not set) and group_add
// entries (scalar values; a group_add that isn't a list is refused).
func composeIDs(compose []byte) (users map[string]string, groupAdd map[string][]string, err error) {
	var doc struct {
		Services map[string]struct {
			User     yaml.Node `yaml:"user"`
			GroupAdd yaml.Node `yaml:"group_add"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(compose, &doc); err != nil {
		return nil, nil, fmt.Errorf("compose.yml: %v", err)
	}
	users, groupAdd = map[string]string{}, map[string][]string{}
	for svc, s := range doc.Services {
		u, err := idScalar(&s.User)
		if err != nil {
			return nil, nil, fmt.Errorf("service %s: user: %v", svc, err)
		}
		if u != nil {
			users[svc] = *u
		}
		switch g := resolveAlias(&s.GroupAdd); {
		case g.Kind == 0 || (g.Kind == yaml.ScalarNode && g.Tag == "!!null"):
		case g.Kind == yaml.SequenceNode:
			for _, e := range g.Content {
				v, err := idScalar(e)
				if err != nil || v == nil {
					return nil, nil, fmt.Errorf("service %s: group_add entries must be numbers or names", svc)
				}
				groupAdd[svc] = append(groupAdd[svc], *v)
			}
		default:
			return nil, nil, fmt.Errorf("service %s: group_add must be a list", svc)
		}
	}
	return users, groupAdd, nil
}

// resolveAlias follows YAML aliases (user: *u) to the anchored node.
func resolveAlias(n *yaml.Node) *yaml.Node {
	for i := 0; n.Kind == yaml.AliasNode && n.Alias != nil && i < 32; i++ {
		n = n.Alias
	}
	return n
}

// idScalar is a user: / group_add value as compose reads it (nil = not
// set): aliases followed, and an !!int decoded as YAML does (0165141 is
// octal 60001; 0x… hex) and written in decimal, so the range checks see
// the number Docker gets.
func idScalar(n *yaml.Node) (*string, error) {
	n = resolveAlias(n)
	switch {
	case n.Kind == 0 || (n.Kind == yaml.ScalarNode && n.Tag == "!!null"):
		return nil, nil
	case n.Kind != yaml.ScalarNode:
		return nil, fmt.Errorf("want a scalar")
	case n.Tag == "!!int":
		var i int64
		if err := n.Decode(&i); err != nil {
			return nil, err
		}
		v := strconv.FormatInt(i, 10)
		return &v, nil
	}
	v := n.Value
	return &v, nil
}

// singleRefRe is the only accepted interpolation form of a gid (or uid)
// source: exactly $NAME, ${NAME}, or ${NAME:-n} / ${NAME-n}
// with a plain whole-number n (range-checked) — nothing around it, no
// nesting, no $ in the fallback, no ${NAME?err} and no ${NAME:+n} /
// ${NAME+n} (compose substitutes n when NAME is set: a parser
// differential; security review). groupNameRe is a plain group name
// (group_add only) or user name (the uid part).
var (
	singleRefRe = regexp.MustCompile(`^(?:\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?-)([0-9]{1,10}))?\}|\$([A-Za-z_][A-Za-z0-9_]*))$`)
	// braceRefRe is a ${…} whose fallback (if any) is only digits.
	braceRefRe  = regexp.MustCompile(`^\$\{[A-Za-z_][A-Za-z0-9_]*(?:[:?+-]{1,2}[0-9]*)?\}`)
	groupNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*$`)
)

// gidRefRe is an interpolation in a gid source: ${NAME}, ${NAME<op>value}
// (op -, :-, +, :+, ?, :?) or $NAME.
var gidRefRe = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?[-+?])([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)`)

// composeGIDs refuses a gid in the folder gid range on any service: a
// literal compose user: gid or group_add entry, an interpolation's
// default (${X:-n}, ${X-n}) or alternative value (${X:+n}), and the
// default of the option an interpolation names (security-hook ruling 1).
func (v *specCheck) composeGIDs() error {
	seen := map[string]bool{}
	var svcs []string
	for s := range v.users {
		seen[s] = true
		svcs = append(svcs, s)
	}
	for s := range v.groupAdd {
		if !seen[s] {
			svcs = append(svcs, s)
		}
	}
	sort.Strings(svcs)
	for _, s := range svcs {
		u := v.users[s]
		if err := userFallbacks(s, u); err != nil {
			return err
		}
		uid, g, ok := splitUser(u)
		if u != "" && !userNumRe.MatchString(uid) && !groupNameRe.MatchString(uid) && !singleRefRe.MatchString(uid) {
			return fmt.Errorf("service %s: compose user: uid %q must be a whole number, a user name or exactly one ${NAME} / $NAME (no mixed forms)", s, uid)
		}
		if err := v.intRef(s, "compose user: uid", uid); err != nil {
			return err
		}
		if ok {
			if err := v.gidSource(s, "compose user: gid", "compose user: gid", g, false); err != nil {
				return err
			}
		}
		for _, e := range v.groupAdd[s] {
			if err := v.gidSource(s, "group_add gid", "group_add", e, true); err != nil {
				return err
			}
		}
	}
	return nil
}

// intRef: a ${NAME} / $NAME uid or gid source must name an instance int
// option of this template (follow-up 3): a string option or an undeclared
// variable (Expert env, core env) could expand to "1000:60001"; an int
// can't hold ':', and its default is range-checked. what names the source.
func (v *specCheck) intRef(svc, what, val string) error {
	m := singleRefRe.FindStringSubmatch(val)
	if m == nil {
		return nil
	}
	name := m[1]
	if name == "" {
		name = m[4]
	}
	if v.envOption(name) == nil {
		return fmt.Errorf("service %s: %s ${%s} must name an instance int option of this template (not a string option, an undeclared variable or PORTCULLIS_*)", svc, what, name)
	}
	return nil
}

// userFallbacks refuses a compose user: whose ${…} fallbacks hold
// anything but digits (a ':' there would move compose's uid/gid split,
// a '$' nest another value), checked before splitUser.
func userFallbacks(svc, u string) error {
	for i := 0; i < len(u); i++ {
		if u[i] != '$' || i+1 >= len(u) {
			continue
		}
		if u[i+1] == '$' {
			i++
			continue
		}
		if u[i+1] == '{' && !braceRefRe.MatchString(u[i:]) {
			return fmt.Errorf("service %s: compose user: %q: a ${…} fallback may only be a whole number (no ':', '$' or nesting)", svc, u)
		}
	}
	return nil
}

// gidSource checks one gid source value of service svc. lit prefixes a
// number's refusal, ref an option reference's; names admits a plain
// group name (group_add). Anything but a whole number, a name or exactly
// one ${…} / $NAME is refused: a mixed form (${X:-6}0001, ${A}${B},
// nesting, $$-escapes) could compose a gid no check sees.
func (v *specCheck) gidSource(svc, lit, ref, val string, names bool) error {
	if userNumRe.MatchString(val) {
		if n, _ := strconv.ParseInt(val, 10, 64); InFolderGIDRange(n) {
			return fmt.Errorf("service %s: %s %d is in %s", svc, lit, n, gidRangeText)
		}
		return nil
	}
	if names && groupNameRe.MatchString(val) {
		return nil
	}
	if !singleRefRe.MatchString(val) {
		if names {
			return fmt.Errorf("service %s: group_add entry %q must be a whole number, a group name or exactly one ${NAME} / $NAME (no mixed forms)", svc, val)
		}
		return fmt.Errorf("service %s: compose user: gid %q must be a whole number or exactly one ${NAME} / $NAME (no mixed forms)", svc, val)
	}
	if err := v.intRef(svc, ref, val); err != nil {
		return err
	}
	for _, m := range interpolations(val, gidRefRe) {
		name, op, value := m[1], m[2], m[3]
		if name == "" {
			name = m[4]
		}
		if op != "" && op != "?" && op != ":?" && userNumRe.MatchString(value) {
			if n, _ := strconv.ParseInt(value, 10, 64); InFolderGIDRange(n) {
				return fmt.Errorf("service %s: %s %d (the default of ${%s}) is in %s", svc, lit, n, name, gidRangeText)
			}
		}
		if ro := v.envOption(name); ro != nil {
			if d, _, in := idDefault(ro); in {
				return fmt.Errorf("service %s: %s ${%s} is setting %s, whose default %d is in %s", svc, ref, name, ro.Key, d, gidRangeText)
			}
		}
	}
	return nil
}

// anyEnvOption is the instance option (any type) that delivers env name
// (any of its EnvNames).
func (v *specCheck) anyEnvOption(name string) *Option {
	if v.m.Settings == nil {
		return nil
	}
	for i := range v.m.Settings.Options {
		ro := &v.m.Settings.Options[i]
		if ro.EffectiveScope() == ScopeInstance && slices.Contains(ro.EnvNames(), name) {
			return ro
		}
	}
	return nil
}

// groupAddResolves: next to a folder block every group_add entry of the
// target service is a number or one ${NAME} of an instance int option
// (security-hook ruling 1: no gid the Hub can't see).
func (v *specCheck) groupAddResolves(svc string) error {
	for _, e := range v.groupAdd[svc] {
		if userNumRe.MatchString(e) {
			continue
		}
		if p := parseUserPart(e); p.env != "" && v.envOption(p.env) != nil {
			continue
		}
		return fmt.Errorf("service %s's group_add entry %q next to a folder block must be a number or ${NAME} of an instance int option", svc, e)
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

// EffectiveMode is how o's path is mounted: "ro" or "rw". A folder block
// decides it (access read is always read-only, also on a custom host
// path, and wins over a stray mode); otherwise mode, default rw.
func (o *Option) EffectiveMode() string {
	if o.Folder != nil {
		if o.Folder.Access == FolderWrite {
			return "rw"
		}
		return "ro"
	}
	if o.Mode == "ro" {
		return "ro"
	}
	return "rw"
}
