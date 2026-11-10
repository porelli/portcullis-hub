package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/signin"
)

// The Portcullis MCP's sign-in management tools (contract §8.1, §15.10):
// admin tools mirroring the sign-in routes, with per-call classes. A
// sign-in call is W only when the new rule implies the old one with the
// switched-on methods and with every available method on, nobody is
// newly blocked and nobody's methods are unknown (signInClass); switching
// a method or add_stronger on is always D. Everything else fails closed
// to D.

func init() {
	// Free-form arguments: the sign-in rule is a recursive JSON structure
	// (signin.Node), so we use json.RawMessage and validate it in the tool.
	for k, why := range map[string]string{
		"save_sign_in_template.rule":    "the sign-in rule (recursive JSON: groups nest, each containing method ids or more groups)",
		"preview_sign_in_template.rule": "the sign-in rule (recursive JSON: groups nest, each containing method ids or more groups)",
	} {
		mcpFreeFormAllow[k] = why
	}
}

// registerSignInTools registers the sign-in MCP tools.
func (s *Server) registerSignInTools() {
	for _, t := range []Tool{
		admin("get_sign_in", "The sign-in methods and templates: which methods are switched on, the templates' rules and what uses them, warnings when people can't get in.",
			ClassRead, "GET /api/signin", "", func(ctx context.Context, _ directory.Actor, _ noArgs) (any, error) {
				return s.signInView(ctx)
			}),

		admin("get_instance_sign_in", "An app's sign-in template: the one that applies (its own pick or the default), the templates it can pick and who can't meet it.",
			ClassRead, "GET /api/instances/{id}/signin", "", func(ctx context.Context, _ directory.Actor, in idArgs) (any, error) {
				if err := instanceIDOK(in.ID); err != nil {
					return nil, err
				}
				return s.instanceSignIn(ctx, in.ID)
			}),

		{
			Name:         "set_sign_in_method",
			Description:  "Switch a sign-in method on or off for the whole server. Switching one on needs your confirmation in the browser; so does switching one off when that blocks someone or who has which method can't be read.",
			Class:        ClassDestructive,
			Scope:        ScopeAdmin,
			Twin:         "PUT /api/signin/methods/{method}",
			Audit:        "signin.method",
			In:           &signInMethodArgs{},
			ClassFor:     s.setSignInMethodClass,
			Precheck:     s.signInPrecheck("set_sign_in_method"),
			Typed:        argReader("method"),
			Consequences: s.setSignInMethodConsequences,
			Run: func(ctx context.Context, c *directory.Caller, args json.RawMessage) (any, error) {
				in, err := decode[signInMethodArgs](args)
				if err != nil {
					return nil, badArg("invalid arguments")
				}
				return s.setMethod(ctx, toolActor(ctx, c), in.Method, in.On)
			},
		},

		{
			Name:         "save_sign_in_template",
			Description:  "Create (create: true) or update a sign-in template. An update to a weaker rule, or one that blocks someone (or while who has which method can't be read), needs your confirmation in the browser.",
			Class:        ClassDestructive,
			Scope:        ScopeAdmin,
			Twin:         "POST /api/signin/templates",
			AlsoTwins:    []string{"PUT /api/signin/templates/{id}"},
			Audit:        "signin.template",
			In:           &signInTemplateArgs{},
			ClassFor:     s.saveSignInTemplateClass,
			Precheck:     s.signInPrecheck("save_sign_in_template"),
			Typed:        argReader("id"),
			Consequences: s.saveSignInTemplateConsequences,
			Run: func(ctx context.Context, c *directory.Caller, args json.RawMessage) (any, error) {
				in, err := decode[signInTemplateArgs](args)
				if err != nil {
					return nil, badArg("invalid arguments")
				}
				var rule signin.Node
				if err := json.Unmarshal(in.Rule, &rule); err != nil {
					return nil, badArg("invalid rule")
				}
				return s.saveSignInTemplate(ctx, toolActor(ctx, c), in.ID, hub.TemplateInput{Name: in.Name, Rule: rule}, in.Create)
			},
		},

		admin("set_sign_in_template_enabled", "Enable or disable a sign-in template (one in use can't be disabled).",
			ClassWrite, "PUT /api/signin/templates/{id}/enabled", "signin.template_enabled", func(ctx context.Context, a directory.Actor, in signInTemplateEnabledArgs) (any, error) {
				return s.setTemplateEnabled(ctx, a, in.ID, in.On)
			}),

		admin("delete_sign_in_template", "Delete a sign-in template (not a built-in one, not one in use).",
			ClassWrite, "DELETE /api/signin/templates/{id}", "signin.template_delete", func(ctx context.Context, a directory.Actor, in signInTemplateIDArgs) (any, error) {
				return nil, s.deleteTemplate(ctx, a, in.ID)
			}),

		{
			Name:        "preview_sign_in_template",
			Description: "Preview a sign-in template: its score, its sentence and, for an existing template, who it would block where it is used.",
			Class:       ClassRead,
			Scope:       ScopeAdmin,
			Twin:        "POST /api/signin/templates/preview",
			In:          &signInPreviewArgs{},
			Run: func(ctx context.Context, c *directory.Caller, args json.RawMessage) (any, error) {
				in, err := decode[signInPreviewArgs](args)
				if err != nil {
					return nil, badArg("invalid arguments")
				}
				var rule signin.Node
				if err := json.Unmarshal(in.Rule, &rule); err != nil {
					return nil, badArg("invalid rule")
				}
				return s.previewTemplate(ctx, in.ID, hub.TemplateInput{Name: in.Name, Rule: rule})
			},
		},

		{
			Name:         "set_default_template",
			Description:  "Set the Portcullis-wide default sign-in template. A weaker template, or one that blocks someone (or while who has which method can't be read), needs your confirmation in the browser.",
			Class:        ClassDestructive,
			Scope:        ScopeAdmin,
			Twin:         "PUT /api/signin/default",
			Audit:        "signin.default",
			In:           &signInDefaultArgs{},
			ClassFor:     s.setDefaultTemplateClass,
			Precheck:     s.signInPrecheck("set_default_template"),
			Typed:        argReader("template"),
			Consequences: s.setDefaultTemplateConsequences,
			Run: func(ctx context.Context, c *directory.Caller, args json.RawMessage) (any, error) {
				in, err := decode[signInDefaultArgs](args)
				if err != nil {
					return nil, badArg("invalid arguments")
				}
				return s.setDefaultTemplate(ctx, toolActor(ctx, c), in.Template)
			},
		},

		{
			Name:         "set_core_template",
			Description:  "Set a core page's sign-in template (\"\" = the default). A weaker template, or one that blocks someone (or while who has which method can't be read), needs your confirmation in the browser.",
			Class:        ClassDestructive,
			Scope:        ScopeAdmin,
			Twin:         "PUT /api/signin/core/{key}",
			Audit:        "signin.core",
			In:           &signInCoreArgs{},
			ClassFor:     s.setCoreTemplateClass,
			Precheck:     s.signInPrecheck("set_core_template"),
			Typed:        argReader("key"),
			Consequences: s.setCoreTemplateConsequences,
			Run: func(ctx context.Context, c *directory.Caller, args json.RawMessage) (any, error) {
				in, err := decode[signInCoreArgs](args)
				if err != nil {
					return nil, badArg("invalid arguments")
				}
				return s.setCoreTemplate(ctx, toolActor(ctx, c), in.Key, in.Template)
			},
		},

		{
			Name:         "set_sign_in_template",
			Description:  "Set an app's sign-in template (\"\" = the default). A weaker template, or one that blocks someone (or while who has which method can't be read), needs your confirmation in the browser.",
			Class:        ClassDestructive,
			Scope:        ScopeAdmin,
			Twin:         "PUT /api/instances/{id}/settings",
			Audit:        "settings.change",
			In:           &signInPickArgs{},
			ClassFor:     s.setSignInTemplateClass,
			Precheck:     s.signInPrecheck("set_sign_in_template"),
			Typed:        idOf,
			Consequences: s.setSignInTemplateConsequences,
			Run: func(ctx context.Context, c *directory.Caller, args json.RawMessage) (any, error) {
				in, err := decode[signInPickArgs](args)
				if err != nil {
					return nil, badArg("invalid arguments")
				}
				if err := instanceIDOK(in.ID); err != nil {
					return nil, err
				}
				return s.saveSettings(toolActor(ctx, c), in.ID, hub.SettingsUpdate{SignInTemplate: &in.Template})
			},
		},

		{
			Name:        "set_add_stronger",
			Description: "Let people add any sign-in method, not only ones as strong as what they signed in with (turning this on needs your confirmation in the browser).",
			Class:       ClassDestructive,
			Scope:       ScopeAdmin,
			Twin:        "PUT /api/signin/add-stronger",
			Audit:       "signin.add_stronger",
			In:          &signInAddStrongerArgs{},
			ClassFor:    s.setAddStrongerClass,
			Typed: func(args json.RawMessage) string {
				var a signInAddStrongerArgs
				if json.Unmarshal(args, &a) != nil {
					return "set_add_stronger"
				}
				if a.On {
					return "on"
				}
				return "off"
			},
			Consequences: func(ctx context.Context, args json.RawMessage) []string {
				var a signInAddStrongerArgs
				if json.Unmarshal(args, &a) != nil {
					return nil
				}
				if a.On {
					return []string{"People will be able to add any method, also one weaker than what they signed in with"}
				}
				return []string{"People will only add methods as strong as what they signed in with"}
			},
			Run: func(ctx context.Context, c *directory.Caller, args json.RawMessage) (any, error) {
				in, err := decode[signInAddStrongerArgs](args)
				if err != nil {
					return nil, badArg("invalid arguments")
				}
				return nil, s.setAddStronger(ctx, toolActor(ctx, c), in.On)
			},
		},
	} {
		s.registerTool(t)
	}
}

// Argument types for sign-in tools.
type (
	signInMethodArgs struct {
		Method signin.Method `json:"method" jsonschema:"the method id (password, passkey_synced, browser_cert, passkey_device, security_key, yubikey_cert)"`
		On     bool          `json:"on" jsonschema:"true switches it on (needs your confirmation), false off"`
	}
	signInTemplateArgs struct {
		ID     string          `json:"id" jsonschema:"the template id (^[a-z][a-z0-9-]{0,31}$)"`
		Name   string          `json:"name" jsonschema:"the template's name (1-48 visible characters)"`
		Rule   json.RawMessage `json:"rule" jsonschema:"the sign-in rule (a group op:any|all, items:[method ids, families, nested groups])"`
		Create bool            `json:"create,omitempty" jsonschema:"true creates it, false (default) updates"`
	}
	signInTemplateEnabledArgs struct {
		ID string `json:"id" jsonschema:"the template id"`
		On bool   `json:"on" jsonschema:"true enables it, false disables"`
	}
	signInTemplateIDArgs struct {
		ID string `json:"id" jsonschema:"the template id"`
	}
	signInPreviewArgs struct {
		ID   string          `json:"id,omitempty" jsonschema:"the template id (for an existing template; shows what it affects)"`
		Name string          `json:"name" jsonschema:"the template's name"`
		Rule json.RawMessage `json:"rule" jsonschema:"the sign-in rule"`
	}
	signInDefaultArgs struct {
		Template string `json:"template" jsonschema:"the template id to set as default"`
	}
	signInCoreArgs struct {
		Key      string `json:"key" jsonschema:"the core page key (portal, hub, people, directory, enroll, metrics, traefik)"`
		Template string `json:"template" jsonschema:"the template id (empty string = the default)"`
	}
	signInPickArgs struct {
		ID       string `json:"id" jsonschema:"the instance id"`
		Template string `json:"template" jsonschema:"the template id (empty string = the default)"`
	}
	signInAddStrongerArgs struct {
		On bool `json:"on" jsonschema:"true allows adding any method, false only methods as strong as the session's"`
	}
)

// signInDraftOf is tool's arguments as the Hub's draft (false: they don't
// decode, or the tool isn't a sign-in change).
func signInDraftOf(tool string, args json.RawMessage) (hub.SignInDraft, bool) {
	switch tool {
	case "set_sign_in_method":
		a, err := decode[signInMethodArgs](args)
		if err != nil || a.Method == "" {
			return hub.SignInDraft{}, false
		}
		return hub.SignInDraft{Method: a.Method, On: a.On}, true
	case "save_sign_in_template":
		a, err := decode[signInTemplateArgs](args)
		if err != nil {
			return hub.SignInDraft{}, false
		}
		d := hub.SignInDraft{Template: a.ID, Name: a.Name, Create: a.Create}
		if len(a.Rule) > 0 && string(a.Rule) != "null" {
			var rule signin.Node
			if json.Unmarshal(a.Rule, &rule) != nil {
				return hub.SignInDraft{}, false
			}
			d.Rule = &rule
		}
		return d, true
	case "set_default_template":
		a, err := decode[signInDefaultArgs](args)
		if err != nil {
			return hub.SignInDraft{}, false
		}
		return hub.SignInDraft{Default: &a.Template}, true
	case "set_core_template":
		a, err := decode[signInCoreArgs](args)
		if err != nil {
			return hub.SignInDraft{}, false
		}
		return hub.SignInDraft{CoreKey: a.Key, Core: &a.Template}, true
	case "set_sign_in_template":
		a, err := decode[signInPickArgs](args)
		if err != nil {
			return hub.SignInDraft{}, false
		}
		return hub.SignInDraft{Instance: a.ID, Pick: &a.Template}, true
	}
	return hub.SignInDraft{}, false
}

// signInPrecheck refuses, before any confirmation, what tool's twin
// route would refuse for the call's names and rule (hub.PrecheckSignIn:
// the route's status and text).
func (s *Server) signInPrecheck(tool string) func(context.Context, *directory.Caller, json.RawMessage) error {
	return func(_ context.Context, _ *directory.Caller, args json.RawMessage) error {
		d, ok := signInDraftOf(tool, args)
		if !ok {
			if tool == "save_sign_in_template" {
				return badArg("invalid rule")
			}
			return badArg("invalid arguments")
		}
		if d.Pick != nil {
			if err := instanceIDOK(d.Instance); err != nil {
				return err
			}
		}
		return s.Hub.PrecheckSignIn(d)
	}
}

// impliesBoth reports whether newRule implies oldRule both with the
// switched-on methods and with every available method on (a dormant
// alternative widens once its method is switched on). Any rule that
// doesn't compile in either judgement: false (fail closed).
func impliesBoth(view *hub.SignInView, newRule, oldRule signin.Node) bool {
	on, all := map[signin.Method]bool{}, map[signin.Method]bool{}
	for _, m := range view.Methods {
		if m.On {
			on[m.ID] = true
		}
		if m.Available {
			all[m.ID] = true
		}
	}
	for _, set := range []map[signin.Method]bool{on, all} {
		n, err := signin.Compile(newRule, set)
		if err != nil {
			return false
		}
		o, err := signin.Compile(oldRule, set)
		if err != nil {
			return false
		}
		if !signin.Implies(n, o) {
			return false
		}
	}
	return true
}

// templateOf is template id's view in view (nil: unknown).
func templateOf(view *hub.SignInView, id string) *hub.SignInTemplateView {
	for i := range view.Templates {
		if view.Templates[i].ID == id {
			return &view.Templates[i]
		}
	}
	return nil
}

// signInClass is the W rule's second half: W only when nobody is newly
// blocked and nobody is unknown (hub.NewlyBlocked: the membership and the
// cached inventory, never a forced refresh).
func (s *Server) signInClass(ctx context.Context, d hub.SignInDraft) ToolClass {
	imp := s.Hub.NewlyBlocked(ctx, d)
	if imp == nil || imp.Unknown != "" || len(imp.Affected) > 0 {
		return ClassDestructive
	}
	return ClassWrite
}

// pickClass is the class of a pick moving from template oldID to newID:
// W only when both are known enabled templates, newID's rule implies
// oldID's (impliesBoth) and nobody is newly blocked.
func (s *Server) pickClass(ctx context.Context, view *hub.SignInView, oldID, newID string, d hub.SignInDraft) ToolClass {
	o, n := templateOf(view, oldID), templateOf(view, newID)
	if o == nil || n == nil || !n.Enabled {
		return ClassDestructive
	}
	if !impliesBoth(view, n.Rule, o.Rule) {
		return ClassDestructive
	}
	return s.signInClass(ctx, d)
}

// setSignInMethodClass: on is always D (§15.10); off is W only when every
// in-use template still compiles, implies what it was and nobody is newly
// blocked.
func (s *Server) setSignInMethodClass(ctx context.Context, args json.RawMessage) ToolClass {
	a, err := decode[signInMethodArgs](args)
	if err != nil || a.On || a.Method == "" {
		return ClassDestructive
	}
	view := s.Hub.SignInState()
	before, after := map[signin.Method]bool{}, map[signin.Method]bool{}
	for _, m := range view.Methods {
		if m.On {
			before[m.ID], after[m.ID] = true, true
		}
	}
	delete(after, a.Method)
	for _, t := range view.Templates {
		if !t.Enabled {
			continue
		}
		b, errB := signin.Compile(t.Rule, before)
		n, errA := signin.Compile(t.Rule, after)
		if errB != nil || errA != nil || !signin.Implies(n, b) {
			return ClassDestructive
		}
	}
	return s.signInClass(ctx, hub.SignInDraft{Method: a.Method, On: false})
}

// saveSignInTemplateClass: a create is W (nothing uses a new template);
// an update is W only when the new rule implies the old one with the
// switched-on methods and with every available method on, and nobody is
// newly blocked.
func (s *Server) saveSignInTemplateClass(ctx context.Context, args json.RawMessage) ToolClass {
	d, ok := signInDraftOf("save_sign_in_template", args)
	if !ok || d.Rule == nil {
		return ClassDestructive
	}
	if d.Create {
		return ClassWrite
	}
	view := s.Hub.SignInState()
	old := templateOf(view, d.Template)
	if old == nil || !impliesBoth(view, *d.Rule, old.Rule) {
		return ClassDestructive
	}
	return s.signInClass(ctx, d)
}

// setDefaultTemplateClass: W only when the new default implies the
// current one and nobody is newly blocked.
func (s *Server) setDefaultTemplateClass(ctx context.Context, args json.RawMessage) ToolClass {
	d, ok := signInDraftOf("set_default_template", args)
	if !ok {
		return ClassDestructive
	}
	view := s.Hub.SignInState()
	return s.pickClass(ctx, view, view.Default, *d.Default, d)
}

// setCoreTemplateClass: the core page's effective template ("" = the
// default) before and after, as setDefaultTemplateClass.
func (s *Server) setCoreTemplateClass(ctx context.Context, args json.RawMessage) ToolClass {
	d, ok := signInDraftOf("set_core_template", args)
	if !ok {
		return ClassDestructive
	}
	view := s.Hub.SignInState()
	oldID, newID := view.Core[d.CoreKey], *d.Core
	if oldID == "" {
		oldID = view.Default
	}
	if newID == "" {
		newID = view.Default
	}
	return s.pickClass(ctx, view, oldID, newID, d)
}

// setSignInTemplateClass: the instance's effective template ("" = the
// default) before and after, as setDefaultTemplateClass. An instance that
// takes no template, or can't be read: D.
func (s *Server) setSignInTemplateClass(ctx context.Context, args json.RawMessage) ToolClass {
	d, ok := signInDraftOf("set_sign_in_template", args)
	if !ok || instanceIDOK(d.Instance) != nil {
		return ClassDestructive
	}
	cur, err := s.Hub.AppSettings(d.Instance)
	if err != nil || !cur.Capability.Templates {
		return ClassDestructive
	}
	view := s.Hub.SignInState()
	oldID, newID := cur.SignInTemplate, *d.Pick
	if oldID == "" {
		oldID = view.Default
	}
	if newID == "" {
		newID = view.Default
	}
	return s.pickClass(ctx, view, oldID, newID, d)
}

// setAddStrongerClass: D when on, W when off.
func (s *Server) setAddStrongerClass(_ context.Context, args json.RawMessage) ToolClass {
	a, err := decode[signInAddStrongerArgs](args)
	if err != nil || a.On {
		return ClassDestructive
	}
	return ClassWrite
}

// ── Consequences ──

// impactLines names who d newly blocks, per use, or why that isn't known.
func (s *Server) impactLines(ctx context.Context, d hub.SignInDraft) []string {
	imp := s.Hub.NewlyBlocked(ctx, d)
	if imp == nil {
		return []string{"Who this blocks couldn't be worked out."}
	}
	var out []string
	if imp.Unknown != "" {
		out = append(out, "Who this blocks isn't known: "+imp.Unknown+".")
	}
	for _, a := range imp.Affected {
		users := make([]string, 0, len(a.Blocked))
		for _, b := range a.Blocked {
			users = append(users, q(b.User)+" ("+b.Why+")")
		}
		out = append(out, fmt.Sprintf("%s: %d newly blocked: %s", q(a.Name), len(a.Blocked), strings.Join(users, ", ")))
	}
	return out
}

// usesText is "used by "a", "b"" (or "not in use").
func usesText(uses []hub.UseRef) string {
	if len(uses) == 0 {
		return "not in use"
	}
	names := make([]string, len(uses))
	for i, u := range uses {
		names[i] = q(u.Name)
	}
	return "used by " + strings.Join(names, ", ")
}

// templateText is a template's name (id) and sentence, or its id when
// unknown.
func templateText(view *hub.SignInView, id string) string {
	t := templateOf(view, id)
	if t == nil {
		return q(id)
	}
	return q(t.Name) + " (" + q(id) + "): " + t.Sentence
}

// setSignInMethodConsequences: switching on names each in-use template it
// widens, once; switching off who it blocks.
func (s *Server) setSignInMethodConsequences(ctx context.Context, args json.RawMessage) []string {
	a, err := decode[signInMethodArgs](args)
	if err != nil {
		return nil
	}
	label := string(a.Method)
	if info, ok := signin.InfoOf(a.Method); ok {
		label = info.Label
	}
	if !a.On {
		return append([]string{q(label) + " will no longer be offered at sign-in."}, s.impactLines(ctx, hub.SignInDraft{Method: a.Method})...)
	}
	view := s.Hub.SignInState()
	without, with := map[signin.Method]bool{}, map[signin.Method]bool{}
	for _, m := range view.Methods {
		if m.On {
			without[m.ID], with[m.ID] = true, true
		}
	}
	with[a.Method] = true
	out := []string{q(label) + " will be offered at sign-in."}
	for _, t := range view.Templates {
		if !t.Enabled || len(t.UsedBy) == 0 {
			continue
		}
		before, errB := signin.Compile(t.Rule, without)
		after, errA := signin.Compile(t.Rule, with)
		if errA == nil && (errB != nil || !signin.Implies(after, before)) {
			out = append(out, "It widens template "+q(t.Name)+" ("+usesText(t.UsedBy)+").")
		}
	}
	return out
}

// saveSignInTemplateConsequences: the new rule, what uses the template and
// who it blocks.
func (s *Server) saveSignInTemplateConsequences(ctx context.Context, args json.RawMessage) []string {
	d, ok := signInDraftOf("save_sign_in_template", args)
	if !ok || d.Rule == nil {
		return nil
	}
	sent := signin.Sentence(*d.Rule)
	if d.Create {
		return []string{"A new template " + q(d.Name) + " (" + q(d.Template) + ") will be created: " + sent}
	}
	view := s.Hub.SignInState()
	var uses []hub.UseRef
	if t := templateOf(view, d.Template); t != nil {
		uses = t.UsedBy
	}
	out := []string{"Template " + q(d.Template) + " will be changed to " + q(d.Name) + ": " + sent,
		"Template " + q(d.Template) + " is " + usesText(uses) + "."}
	return append(out, s.impactLines(ctx, d)...)
}

// setDefaultTemplateConsequences: the new default, what inherits it and
// who it blocks.
func (s *Server) setDefaultTemplateConsequences(ctx context.Context, args json.RawMessage) []string {
	d, ok := signInDraftOf("set_default_template", args)
	if !ok {
		return nil
	}
	view := s.Hub.SignInState()
	out := []string{"The default template will be " + templateText(view, *d.Default),
		"It applies to " + inheritText(s.Hub.InheritingDefault()) + "."}
	return append(out, s.impactLines(ctx, d)...)
}

// inheritText names the core pages and apps that use the default.
func inheritText(uses []hub.UseRef) string {
	var core, apps []string
	for _, u := range uses {
		if u.Kind == hub.UseCore {
			core = append(core, q(u.Name))
		} else {
			apps = append(apps, q(u.Name))
		}
	}
	var parts []string
	if len(core) > 0 {
		parts = append(parts, "the core pages "+strings.Join(core, ", "))
	}
	if len(apps) > 0 {
		parts = append(parts, "the apps "+strings.Join(apps, ", "))
	}
	if len(parts) == 0 {
		return "nothing that inherits it"
	}
	return strings.Join(parts, " and ")
}

// setCoreTemplateConsequences: the core page's new template and who it
// blocks.
func (s *Server) setCoreTemplateConsequences(ctx context.Context, args json.RawMessage) []string {
	d, ok := signInDraftOf("set_core_template", args)
	if !ok {
		return nil
	}
	view := s.Hub.SignInState()
	tmpl := *d.Core
	what := templateText(view, tmpl)
	if tmpl == "" {
		what = "the default, " + templateText(view, view.Default)
	}
	out := []string{"Core page " + q(d.CoreKey) + " will use " + what}
	return append(out, s.impactLines(ctx, d)...)
}

// setSignInTemplateConsequences: the app's new template and who it
// blocks.
func (s *Server) setSignInTemplateConsequences(ctx context.Context, args json.RawMessage) []string {
	d, ok := signInDraftOf("set_sign_in_template", args)
	if !ok {
		return nil
	}
	view := s.Hub.SignInState()
	tmpl := *d.Pick
	what := templateText(view, tmpl)
	if tmpl == "" {
		what = "the default, " + templateText(view, view.Default)
	}
	out := []string{"App " + q(d.Instance) + " will use " + what}
	return append(out, s.impactLines(ctx, d)...)
}
