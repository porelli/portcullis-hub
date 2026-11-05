package templates

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// File sharing (template contract v3 MINOR, integration contracts §13.2,
// §13.16): the person_secret and person_id option types, only on
// router-less custom templates (§3). The Hub knows nothing about Samba:
// the username rule, the info lines and the hook are the template's.

// Routerless reports whether the template is method custom with zero
// HTTP routers (§3; set by Discover — a manifest that wasn't discovered
// is never router-less).
func (m *Manifest) Routerless() bool { return m.Auth.Method == "custom" && m.routerless }

// HasPersonSecret reports whether the template has a person_secret option
// (the Hub UI's File sharing tab).
func (m *Manifest) HasPersonSecret() bool {
	for _, o := range m.Options() {
		if o.Type == TypePersonSecret {
			return true
		}
	}
	return false
}

// routerlessOf is the one router-less rule (Discover and the validator):
// method custom and no HTTP router in the routes.
func routerlessOf(method string, routes *Routes) bool {
	return method == "custom" && routes != nil && len(routes.Info) == 0
}

// fieldUse is one optional field of an option and whether it is set (the
// refusals of fields a type doesn't take).
type fieldUse struct {
	name string
	on   bool
}

// Limits of the file-sharing fields.
const (
	usernameReasonMax = 200 // runes
	usernamePatMax    = 500 // bytes, like a string option's pattern
	reservedNameMax   = 64
	infoLabelMax      = 64  // runes
	infoValueMax      = 500 // runes
)

// UsernamePatternVar is the compose environment variable a template may
// give its container the username rule in ($ doubled).
const UsernamePatternVar = "PORTCULLIS_USERNAME_PATTERN"

// fileSharingFields refuses the two types' own fields on any other type
// (before the type is looked up).
func fileSharingFields(o *Option) error {
	if o.Type != TypePersonSecret {
		for _, f := range []fieldUse{
			{"hash", o.Hash != ""}, {"length", o.Length != 0}, {"revoke_on_leave", o.RevokeOnLeave != nil},
			{"on_restore", o.OnRestore != ""}, {"username", o.Username != nil}, {"mount", o.Mount != nil},
			{"info", o.Info != nil},
		} {
			if f.on {
				return fmt.Errorf("%s is for person_secret options", f.name)
			}
		}
		for _, d := range o.Delivery {
			if d.Bare != "" && o.Type != TypePersonID {
				return fmt.Errorf("delivery: %s is for person_secret options (as delivery: file); other options take a list of deliveries", d.Bare)
			}
		}
	}
	if o.Type != TypePersonID && o.Pool != "" {
		return fmt.Errorf("pool is for person_id options")
	}
	return nil
}

// personFieldsRefused refuses the option fields neither type takes (the
// Hub sets their values: one per person, no default, no rows).
func personFieldsRefused(o *Option, extra ...fieldUse) error {
	fs := []fieldUse{
		{"scope", o.Scope != ""}, {"default", o.Default != nil}, {"required", o.Required},
		{"resolve", o.Resolve != ""}, {"resolve_choices", o.ResolveChoices != nil},
		{"group_values", o.GroupValues != nil}, {"privileged", o.Privileged},
		{"requires", o.Requires != nil}, {"requires_any", o.RequiresAny != nil},
		{"admin_override", o.AdminOverride}, {"unique", o.Unique}, {"generate", o.Generate != nil},
		{"writes_as", o.WritesAs != nil},
	}
	for _, f := range append(fs, extra...) {
		if f.on {
			return fmt.Errorf("%s takes no %s (the Hub sets one value per person)", o.Type, f.name)
		}
	}
	return nil
}

// fileSharingTemplate is both types' precondition (F1): a router-less
// custom template whose access group is the population.
func (v *specCheck) fileSharingTemplate(o *Option) error {
	a := &v.m.Auth
	if !v.routerless || !a.GroupAccess || a.AccessGroup == "" {
		return fmt.Errorf("%s needs a router-less template: auth.method custom with no HTTP router, group_access: true and an auth.access_group (who gets one)", o.Type)
	}
	return nil
}

// personSecret checks a person_secret option (§13.2).
func (v *specCheck) personSecret(o *Option) error {
	if err := v.fileSharingTemplate(o); err != nil {
		return err
	}
	if err := personFieldsRefused(o, fieldUse{"self_visible", o.SelfVisible != nil}, fieldUse{"checks", o.Checks != nil}); err != nil {
		return err
	}
	if o.Hash != HashNT {
		return fmt.Errorf("hash must be %s (the NT hash)", HashNT)
	}
	if o.Length < PersonSecretMinLength {
		return fmt.Errorf("length %d must be at least %d", o.Length, PersonSecretMinLength)
	}
	if o.Length%4 != 0 {
		return fmt.Errorf("length %d must be a multiple of 4 (the password is shown in groups of 4)", o.Length)
	}
	if len(o.Delivery) != 1 || o.Delivery[0].Bare != "file" {
		return fmt.Errorf("a person_secret takes exactly delivery: file (its hash files are mounted at mount); env, claim, header, hook and data-file deliveries are refused")
	}
	if o.Applies != "" && o.Applies != AppliesLive {
		return fmt.Errorf("applies %s: a person_secret applies live (its credential_change hook)", o.Applies)
	}
	if err := v.secretMount(o); err != nil {
		return err
	}
	if o.RevokeOnLeave == nil || !*o.RevokeOnLeave {
		return fmt.Errorf("revoke_on_leave must be true (a person who leaves loses the password)")
	}
	if o.OnRestore != OnRestoreVoid {
		return fmt.Errorf("on_restore must be %s (a restore voids every password)", OnRestoreVoid)
	}
	if err := checkUsernameRule(o.Username); err != nil {
		return err
	}
	for i, l := range o.Info {
		if err := v.infoLine(l); err != nil {
			return fmt.Errorf("info[%d]: %w", i, err)
		}
	}
	for _, h := range v.m.Hooks {
		if h.Service == o.Mount.Service && contains(h.When, HookCredentialChange) {
			return nil
		}
	}
	return fmt.Errorf("a person_secret needs a hook on service %s (its mount.service) whose when lists credential_change: it applies revocations live", o.Mount.Service)
}

// secretMount checks a person_secret's mount: an existing service, a
// clean absolute container directory, clear of the path options'
// targets, the data files' mounts and the other person_secret mounts on
// that service.
func (v *specCheck) secretMount(o *Option) error {
	mt := o.Mount
	if mt == nil {
		return fmt.Errorf("a person_secret needs mount {service, path}: where its hash files are mounted read-only")
	}
	if !v.services[mt.Service] {
		return fmt.Errorf("mount.service %s is not in compose.yml", mt.Service)
	}
	if !validMount(mt.Path) {
		return fmt.Errorf("mount.path %q must be an absolute, clean container directory (no ':')", mt.Path)
	}
	for _, f := range v.m.Files {
		if f.Service == mt.Service && nested(f.Mount, mt.Path) {
			return fmt.Errorf("mount.path %s collides with files[%s] (%s) on service %s", mt.Path, f.Name, f.Mount, mt.Service)
		}
	}
	for i := range v.m.Settings.Options {
		p := &v.m.Settings.Options[i]
		if p == o || p.Key == o.Key {
			continue
		}
		switch {
		case p.Type == TypePath && p.Target != nil && p.Target.Service == mt.Service && nested(p.Target.Mount, mt.Path):
			return fmt.Errorf("mount.path %s collides with setting %s's target %s on service %s", mt.Path, p.Key, p.Target.Mount, mt.Service)
		case p.Type == TypePersonSecret && p.Mount != nil && p.Mount.Service == mt.Service && nested(p.Mount.Path, mt.Path) && v.before(p, o):
			return fmt.Errorf("mount.path %s collides with setting %s's mount %s on service %s", mt.Path, p.Key, p.Mount.Path, mt.Service)
		}
	}
	return nil
}

// before reports whether option p is declared before o.
func (v *specCheck) before(p, o *Option) bool {
	for i := range v.m.Settings.Options {
		switch &v.m.Settings.Options[i] {
		case p:
			return true
		case o:
			return false
		}
	}
	return false
}

// checkUsernameRule checks a person_secret's username rule (nil = none).
func checkUsernameRule(u *UsernameRule) error {
	if u == nil {
		return nil
	}
	if u.Pattern != "" {
		if err := usernamePattern(u.Pattern); err != nil {
			return fmt.Errorf("username.pattern %q: %w", u.Pattern, err)
		}
	}
	for _, r := range u.Reserved {
		if r == "" || len(r) > reservedNameMax || r != strings.ToLower(r) || HasControlChars(r) || strings.ContainsAny(r, " \t") {
			return fmt.Errorf("username.reserved %q: want lowercase names (at most %d characters, no spaces)", r, reservedNameMax)
		}
	}
	if strings.TrimSpace(u.Reason) == "" || utf8.RuneCountInString(u.Reason) > usernameReasonMax || HasControlChars(u.Reason) {
		return fmt.Errorf("username.reason must be one line of 1-%d characters (shown to a person whose name the app can't serve)", usernameReasonMax)
	}
	return nil
}

// usernamePattern accepts only the patterns Go's RE2 and busybox ERE
// read alike (§13.2, F37; T15's Python validator mirrors this rule):
//
//	pattern  = "^" atom* "$"
//	atom     = (literal | class) [interval]
//	literal  = a byte 0x21-0x7E other than \ . [ ] { } ( ) | * + ? ^ $
//	class    = "[" ["^"] item+ "]"
//	item     = "[:" name ":]" | a byte 0x21-0x7E other than \ [ ]
//	name     = alnum | alpha | digit | lower | upper | xdigit
//	interval = "{" m "}" | "{" m "," n "}"   (decimal, m <= n <= 1000)
//
// So no space, non-ASCII or control character, no backslash, dot,
// alternation, group, flag, *, + or ?, no literal brace or bracket, no
// collating element [. .] or equivalence class [= =], and no {,n} / {m,}.
func usernamePattern(p string) error {
	if len(p) > usernamePatMax {
		return fmt.Errorf("at most %d characters", usernamePatMax)
	}
	if len(p) < 2 || p[0] != '^' || p[len(p)-1] != '$' {
		return fmt.Errorf("must be anchored (^…$)")
	}
	for i := 0; i < len(p); i++ {
		if p[i] < 0x21 || p[i] > 0x7e {
			return fmt.Errorf("only printable ASCII without spaces")
		}
	}
	body := p[1 : len(p)-1]
	for i := 0; i < len(body); {
		var n int
		var err error
		if body[i] == '[' {
			n, err = patternClass(body[i:])
		} else if strings.IndexByte(patternSpecial, body[i]) < 0 {
			n = 1
		} else {
			err = fmt.Errorf("%q at %d is not a literal, a bracket class or an interval after one (only what RE2 and busybox ERE read alike)", body[i], i+1)
		}
		if err != nil {
			return err
		}
		i += n
		if i < len(body) && body[i] == '{' {
			n, err := patternInterval(body[i:])
			if err != nil {
				return err
			}
			i += n
		}
	}
	if _, err := regexp.Compile(p); err != nil {
		return err
	}
	return nil
}

// patternSpecial are the bytes that are never a literal in a username
// pattern.
const patternSpecial = `\.[]{}()|*+?^$`

// patternClasses are the POSIX classes both engines read alike.
var patternClasses = map[string]bool{"alnum": true, "alpha": true, "digit": true, "lower": true, "upper": true, "xdigit": true}

// patternClass reads one bracket class at the start of s: its length.
func patternClass(s string) (int, error) {
	i, items := 1, 0
	if i < len(s) && s[i] == '^' {
		i++
	}
	for i < len(s) {
		switch c := s[i]; {
		case c == ']':
			if items == 0 {
				return 0, fmt.Errorf("an empty bracket class")
			}
			return i + 1, nil
		case strings.HasPrefix(s[i:], "[:"):
			end := strings.Index(s[i+2:], ":]")
			if end < 0 || !patternClasses[s[i+2:i+2+end]] {
				return 0, fmt.Errorf("a bracket class names only [:alnum:], [:alpha:], [:digit:], [:lower:], [:upper:] or [:xdigit:]")
			}
			i += 2 + end + 2
		case c == '[' || c == '\\':
			return 0, fmt.Errorf("%q inside a bracket class (no collating elements [. .] or equivalence classes [= =])", c)
		default:
			i++
		}
		items++
	}
	return 0, fmt.Errorf("an unclosed bracket class")
}

// patternInterval reads one {m} / {m,n} at the start of s: its length.
func patternInterval(s string) (int, error) {
	end := strings.IndexByte(s, '}')
	bad := fmt.Errorf("an interval is {m} or {m,n} with m <= n <= 1000")
	if end < 0 {
		return 0, bad
	}
	ms, ns, two := strings.Cut(s[1:end], ",")
	if !two {
		ns = ms
	}
	m, err1 := patternCount(ms)
	n, err2 := patternCount(ns)
	if err1 != nil || err2 != nil || m > n {
		return 0, bad
	}
	return end + 1, nil
}

func patternCount(s string) (int, error) {
	if s == "" || len(s) > 4 || strings.Trim(s, "0123456789") != "" {
		return 0, fmt.Errorf("not a count")
	}
	n, err := strconv.Atoi(s)
	if err != nil || n > 1000 {
		return 0, fmt.Errorf("not a count")
	}
	return n, nil
}

// Info placeholders (§13.2).
var (
	portKeyRe  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
	infoValueT = map[string]bool{TypeString: true, TypeInt: true, TypeEnum: true, TypeBool: true}
)

// infoLine checks one info line: its label and the placeholders of its
// value.
func (v *specCheck) infoLine(l InfoLine) error {
	if strings.TrimSpace(l.Label) == "" || utf8.RuneCountInString(l.Label) > infoLabelMax || HasControlChars(l.Label) {
		return fmt.Errorf("label must be one line of 1-%d characters", infoLabelMax)
	}
	if l.Value == "" || utf8.RuneCountInString(l.Value) > infoValueMax || HasControlChars(l.Value) {
		return fmt.Errorf("value must be one line of 1-%d characters", infoValueMax)
	}
	s := l.Value
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '}':
			return fmt.Errorf("value %q: a } outside a placeholder", s)
		case '{':
			j := strings.IndexByte(s[i:], '}')
			if j < 0 {
				return fmt.Errorf("value %q: an unclosed {", s)
			}
			if err := v.placeholder(s[i+1 : i+j]); err != nil {
				return fmt.Errorf("value %q: %w", s, err)
			}
			i += j
		}
	}
	return nil
}

// placeholder checks one {…} of an info value (without the braces).
func (v *specCheck) placeholder(p string) error {
	port := func(k string) error {
		if !portKeyRe.MatchString(k) {
			return fmt.Errorf("{%s}: %q is not a port key", p, k)
		}
		for _, pt := range v.m.Ports {
			if pt.Key == k {
				return nil
			}
		}
		return fmt.Errorf("{%s}: no declared port %s (ports[].key)", p, k)
	}
	if p == "user" {
		return nil
	}
	if k, ok := strings.CutPrefix(p, "value:"); ok {
		o := v.opts[k]
		switch {
		case o == nil:
			return fmt.Errorf("{%s}: no such option", p)
		case o.EffectiveScope() != ScopeInstance || !infoValueT[o.Type]:
			return fmt.Errorf("{%s}: only an instance string, int, enum or bool option may be shown", p)
		case o.SelfVisible == nil || !*o.SelfVisible:
			return fmt.Errorf("{%s}: setting %s must set self_visible: true to be shown", p, k)
		}
		return nil
	}
	if k, ok := strings.CutPrefix(p, "port:"); ok {
		return port(k)
	}
	if rest, ok := strings.CutPrefix(p, "port_suffix:"); ok {
		k, def, ok := strings.Cut(rest, ":")
		if !ok {
			return fmt.Errorf("{%s}: want {port_suffix:<KEY>:<default port>}", p)
		}
		if n, err := strconv.Atoi(def); err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != def {
			return fmt.Errorf("{%s}: default %q must be a port number (1-65535)", p, def)
		}
		return port(k)
	}
	return fmt.Errorf("{%s} is not a placeholder ({user}, {value:<key>}, {port:<KEY>}, {port_suffix:<KEY>:<default>})", p)
}

// personID checks a person_id option (§13.2).
func (v *specCheck) personID(o *Option) error {
	if err := v.fileSharingTemplate(o); err != nil {
		return err
	}
	if err := personFieldsRefused(o); err != nil {
		return err
	}
	if _, ok := PersonIDPools[o.Pool]; !ok {
		return fmt.Errorf("pool must be %s (the Hub-wide uid pool)", PoolPOSIXUID)
	}
	if o.SelfVisible == nil || *o.SelfVisible {
		return fmt.Errorf("a person_id needs self_visible: false (never shown on My apps)")
	}
	if err := v.checks(o); err != nil {
		return err
	}
	if len(o.Delivery) == 0 {
		return fmt.Errorf("a person_id needs a file delivery ({file: {name, field}}: the people section of a data file)")
	}
	for _, d := range o.Delivery {
		if d.File == nil || d.Env != "" || d.Claim != nil || d.Header != nil || d.Hook != "" || d.Bare != "" || d.Render != nil {
			return fmt.Errorf("a person_id takes only file deliveries ({file: {name, field}})")
		}
		if err := v.file(o, d.File); err != nil {
			return err
		}
		// Every file it reaches must be applied live by a hook.
		if o.Applies == AppliesLive && v.files_[d.File.Name].OnMembershipChange != MembershipHook {
			return fmt.Errorf("applies: live means a hook applies it: file %s needs on_membership_change: hook", d.File.Name)
		}
	}
	return nil
}

// usernamePatternEnv: a compose PORTCULLIS_USERNAME_PATTERN is a
// person_secret's username.pattern with every $ doubled (§13.2), so the
// script and the Hub apply one rule.
func (v *specCheck) usernamePatternEnv() error {
	patterns := map[string]bool{}
	for _, o := range v.m.Options() {
		if o.Type == TypePersonSecret && o.Username != nil && o.Username.Pattern != "" {
			patterns[o.Username.Pattern] = true
		}
	}
	for _, svc := range sortedServices(v.env) {
		val, ok := v.env[svc][UsernamePatternVar]
		if !ok {
			continue
		}
		if val == nil || strings.Contains(strings.ReplaceAll(*val, "$$", ""), "$") || !patterns[strings.ReplaceAll(*val, "$$", "$")] {
			return fmt.Errorf("compose.yml: service %s: %s must be a person_secret option's username.pattern with every $ written as $$", svc, UsernamePatternVar)
		}
	}
	return nil
}

func sortedServices[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// SecretsVolumeKey is the Hub override's top-level volume key for the
// Hub's secrets volume (contract §6, F15): reserved — no template may
// name it as a volume key, a service volume source or in volumes_from,
// and no custom override may use it.
const SecretsVolumeKey = "portcullis-hub-secrets"

// NamesSecretsVolumeKey: s (folded, trimmed) names or embeds
// SecretsVolumeKey (an interpolated value could produce it).
func NamesSecretsVolumeKey(s string) bool {
	return strings.Contains(FoldKey(s), SecretsVolumeKey)
}
