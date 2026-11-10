package state

import (
	"encoding/json"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/portcullis/hub/internal/signin"
	"github.com/portcullis/hub/internal/templates"
)

// SignIn is Settings → Sign-in as state.yaml keeps it (contract §8.1, D12).
type SignIn struct {
	// Methods: method id → switched on. Every method of signin.Methods
	// has an entry; browser_cert is always false (not available yet).
	Methods map[string]bool `json:"methods" yaml:"methods"`
	// Templates: template id → its definition (the source rule).
	Templates map[string]SignInTemplate `json:"templates" yaml:"templates"`
	// Default is the Portcullis-wide default template's id.
	Default string `json:"default" yaml:"default"`
	// Core: core page key (CoreSignInKeys) → template id, "" = the default.
	Core map[string]string `json:"core" yaml:"core"`
	// AddStronger is the "adding a stronger method" switch (§8.1).
	AddStronger bool `json:"add_stronger" yaml:"add_stronger"`
	// Passwords: lowercase user → the Hub-set password record (D13; never
	// the password).
	Passwords map[string]PasswordRecord `json:"passwords" yaml:"passwords"`
}

// SignInTemplate is one template: its name, its source rule (families
// allowed), whether it is enabled and whether it is a built-in.
type SignInTemplate struct {
	Name    string      `json:"name" yaml:"name"`
	Rule    signin.Node `json:"rule" yaml:"rule"`
	Enabled bool        `json:"enabled" yaml:"enabled"`
	BuiltIn bool        `json:"built_in" yaml:"built_in"`
}

// PasswordRecord is when and by whom the Hub set a person's password.
type PasswordRecord struct {
	SetAt time.Time `json:"set_at" yaml:"set_at"`
	SetBy string    `json:"set_by" yaml:"set_by"`
}

// CoreSignInKeys are the core pages that take a template (D11), in
// display order: portal is the main domain.
var CoreSignInKeys = []string{"portal", "hub", "people", "directory", "enroll", "metrics", "traefik"}

// DefaultSignInTemplate is the default template of a fresh state.
const DefaultSignInTemplate = "standard"

// SignInTemplateIDRe is the rule for template ids (D12).
var SignInTemplateIDRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// SignInNameMaxRunes is the longest template name (D12).
const SignInNameMaxRunes = 48

// defaultMethodOn is a fresh state's switch of m (D1): password and
// browser_cert off, the other four on.
func defaultMethodOn(m signin.Method) bool {
	return m != signin.Password && m != signin.BrowserCert
}

// defaultCore is a fresh state's pick for core page key (D11).
func defaultCore(key string) string {
	if key == "hub" || key == "people" {
		return "strong"
	}
	return ""
}

// EnsureSignIn fills the sign-in defaults (D1, D11, D12) a state lacks: a
// fresh state (no methods, templates, default or core picks at all) gets
// the D1 switches, the four built-ins, Default "standard" and the D11
// core picks. On a stored state it only completes: a method without an
// entry is off (fail closed: a stored section without methods has every
// method off), browser_cert is forced
// off, a missing built-in comes back as it ships (built-ins are never
// deleted), only the built-in ids are BuiltIn, an empty default is
// "standard" and a missing core key gets its D11 pick.
func (s *AppState) EnsureSignIn() {
	si := &s.SignIn
	fresh := len(si.Methods) == 0 && len(si.Templates) == 0 && si.Default == "" && len(si.Core) == 0
	if si.Methods == nil {
		si.Methods = make(map[string]bool, len(signin.Methods))
	}
	for _, m := range signin.Methods {
		if _, ok := si.Methods[string(m)]; !ok {
			si.Methods[string(m)] = fresh && defaultMethodOn(m)
		}
	}
	si.Methods[string(signin.BrowserCert)] = false
	if si.Templates == nil {
		si.Templates = make(map[string]SignInTemplate)
	}
	builtin := map[string]bool{}
	for _, b := range signin.Builtins() {
		builtin[b.ID] = true
		if _, ok := si.Templates[b.ID]; !ok {
			si.Templates[b.ID] = SignInTemplate{Name: b.Name, Rule: b.Rule, Enabled: b.Enabled, BuiltIn: true}
		}
	}
	for id, t := range si.Templates {
		if t.BuiltIn != builtin[id] {
			t.BuiltIn = builtin[id]
			si.Templates[id] = t
		}
	}
	if si.Default == "" {
		si.Default = DefaultSignInTemplate
	}
	if si.Core == nil {
		si.Core = make(map[string]string, len(CoreSignInKeys))
	}
	for _, k := range CoreSignInKeys {
		if _, ok := si.Core[k]; !ok {
			si.Core[k] = defaultCore(k)
		}
	}
	if si.Passwords == nil {
		si.Passwords = make(map[string]PasswordRecord)
	}
}

// MethodsOn is the switched-on methods as signin's map (browser_cert
// never: it isn't available).
func (si SignIn) MethodsOn() map[signin.Method]bool {
	on := make(map[signin.Method]bool, len(signin.Methods))
	for _, m := range signin.Methods {
		if si.Methods[string(m)] && m != signin.BrowserCert {
			on[m] = true
		}
	}
	return on
}

// Clone is a deep copy of si.
func (si SignIn) Clone() SignIn {
	out := si
	out.Methods = maps.Clone(si.Methods)
	out.Core = maps.Clone(si.Core)
	out.Passwords = maps.Clone(si.Passwords)
	if si.Templates != nil {
		out.Templates = make(map[string]SignInTemplate, len(si.Templates))
		for id, t := range si.Templates {
			t.Rule = CloneNode(t.Rule)
			out.Templates[id] = t
		}
	}
	return out
}

// CloneNode is a deep copy of a rule.
func CloneNode(n signin.Node) signin.Node {
	if n.Items == nil {
		return n
	}
	out := n
	out.Items = make([]signin.Node, len(n.Items))
	for i, it := range n.Items {
		out.Items[i] = CloneNode(it)
	}
	return out
}

// CheckSignInName is the template name rule (D12), shared by Load and the
// API: 1–48 runes of one line of visible text (no control, invisible or
// format characters: templates.HasHiddenText), no white space at either
// end. "" = fine.
func CheckSignInName(name string) string {
	switch {
	case strings.TrimSpace(name) == "" && !templates.HasHiddenText(name):
		return "a name is required"
	case templates.HasControlChars(name) || templates.HasHiddenText(name):
		return "the name must be one line of visible text: no control, invisible or format characters"
	case strings.TrimSpace(name) != name:
		return "the name may not start or end with white space"
	case utf8.RuneCountInString(name) > SignInNameMaxRunes:
		return fmt.Sprintf("the name is longer than %d characters", SignInNameMaxRunes)
	}
	return ""
}

// checkSignIn refuses a stored sign-in section that doesn't hold
// together (after EnsureSignIn): unknown methods or core keys, a template
// with a bad id, name or rule, an enabled template that can't be met with
// the stored switches, a default, core or instance pick naming no
// template or a disabled one. A corrupt section never loads (fail
// closed): the Hub's writers never leave one.
func (s *AppState) checkSignIn() error {
	si := s.SignIn
	on := si.MethodsOn()
	pick := func(what, id string) error {
		t, ok := si.Templates[id]
		switch {
		case !ok:
			return fmt.Errorf("%s: %q is not a template", what, id)
		case !t.Enabled:
			return fmt.Errorf("%s: template %q is disabled", what, id)
		}
		return nil
	}
	for m := range si.Methods {
		if !slices.Contains(signin.Methods, signin.Method(m)) {
			return fmt.Errorf("unknown method %q", m)
		}
	}
	for _, id := range slices.Sorted(maps.Keys(si.Templates)) {
		t := si.Templates[id]
		if !SignInTemplateIDRe.MatchString(id) {
			return fmt.Errorf("template id %q", id)
		}
		if why := CheckSignInName(t.Name); why != "" {
			return fmt.Errorf("template %s: %s", id, why)
		}
		if err := signin.Validate(t.Rule); err != nil {
			return fmt.Errorf("template %s: %v", id, err)
		}
		if _, err := signin.Compile(t.Rule, on); t.Enabled && err != nil {
			return fmt.Errorf("template %s is enabled but %v", id, err)
		}
	}
	if err := pick("default", si.Default); err != nil {
		return err
	}
	for k, id := range si.Core {
		if !slices.Contains(CoreSignInKeys, k) {
			return fmt.Errorf("unknown core page %q", k)
		}
		if id != "" {
			if err := pick("core page "+k, id); err != nil {
				return err
			}
		}
	}
	for id, e := range s.Instances {
		if e.SignInTemplate != "" {
			if err := pick("instance "+id, e.SignInTemplate); err != nil {
				return err
			}
		}
	}
	return nil
}

// signInTemplateYAML is SignInTemplate's YAML form: the rule as the
// contract's JSON shape (a leaf is a string, a group {op, items}).
type signInTemplateYAML struct {
	Name    string `yaml:"name"`
	Rule    any    `yaml:"rule"`
	Enabled bool   `yaml:"enabled"`
	BuiltIn bool   `yaml:"built_in"`
}

// MarshalYAML writes the rule in its JSON shape.
func (t SignInTemplate) MarshalYAML() (any, error) {
	b, err := json.Marshal(t.Rule)
	if err != nil {
		return nil, err
	}
	var rule any
	if err := json.Unmarshal(b, &rule); err != nil {
		return nil, err
	}
	return signInTemplateYAML{Name: t.Name, Rule: rule, Enabled: t.Enabled, BuiltIn: t.BuiltIn}, nil
}

// UnmarshalYAML reads the rule through signin's strict JSON decoder.
func (t *SignInTemplate) UnmarshalYAML(n *yaml.Node) error {
	var y signInTemplateYAML
	if err := n.Decode(&y); err != nil {
		return err
	}
	b, err := json.Marshal(y.Rule)
	if err != nil {
		return fmt.Errorf("sign_in template rule: %v", err)
	}
	var rule signin.Node
	if err := json.Unmarshal(b, &rule); err != nil {
		return fmt.Errorf("sign_in template rule: %v", err)
	}
	*t = SignInTemplate{Name: y.Name, Rule: rule, Enabled: y.Enabled, BuiltIn: y.BuiltIn}
	return nil
}
