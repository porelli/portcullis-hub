package httpapi

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/signin"
)

// The Portcullis MCP's sign-in management tools (contract §8.1): admin
// tools mirroring the sign-in routes, with per-call classes for some
// (ClassFor).

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

		// set_sign_in_method: D when on, W when off.
		{
			Name:        "set_sign_in_method",
			Description: "Switch a sign-in method on or off (switching one on needs your confirmation in the browser).",
			Class:       ClassDestructive,
			Scope:       ScopeAdmin,
			Twin:        "PUT /api/signin/methods/{method}",
			Audit:       "signin.method",
			In:          &signInMethodArgs{},
			ClassFor:    s.setSignInMethodClass,
			Typed:       argReader("method"),
			Consequences: func(ctx context.Context, args json.RawMessage) []string {
				var a signInMethodArgs
				if json.Unmarshal(args, &a) != nil {
					return nil
				}
				if !a.On {
					return []string{q(string(a.Method)) + " will no longer be offered"}
				}
				// Switching ON: check which templates this widens
				view, err := s.Hub.SignInView(ctx)
				if err != nil {
					return []string{q(string(a.Method)) + " will be offered at sign-in"}
				}
				withoutMethod := make(map[signin.Method]bool)
				withMethod := make(map[signin.Method]bool)
				for _, m := range view.Methods {
					if m.On {
						withoutMethod[m.ID] = true
						withMethod[m.ID] = true
					}
				}
				withMethod[a.Method] = true
				var widened []string
				for _, t := range view.Templates {
					if !t.Enabled || len(t.UsedBy) == 0 {
						continue
					}
					without, err := signin.Compile(t.Rule, withoutMethod)
					if err != nil {
						continue
					}
					with, err := signin.Compile(t.Rule, withMethod)
					if err != nil {
						continue
					}
					if !signin.Implies(with, without) {
						// This template is widened
						uses := make([]string, 0, len(t.UsedBy))
						for _, u := range t.UsedBy {
							uses = append(uses, q(u.Name))
						}
						widened = append(widened, q(t.Name)+" (used by "+strings.Join(uses, ", ")+")")
					}
				}
				if len(widened) > 0 {
					return append([]string{q(string(a.Method)) + " will be offered, widening: " + strings.Join(widened, "; ")}, widened...)
				}
				return []string{q(string(a.Method)) + " will be offered at sign-in"}
			},
			Run: func(ctx context.Context, c *directory.Caller, args json.RawMessage) (any, error) {
				in, err := decode[signInMethodArgs](args)
				if err != nil {
					return nil, badArg("invalid arguments")
				}
				return s.setMethod(ctx, toolActor(ctx, c), in.Method, in.On)
			},
		},

		// save_sign_in_template: D unless creating, or new Implies old.
		{
			Name:        "save_sign_in_template",
			Description: "Create or update a sign-in template (narrowing access needs your confirmation).",
			Class:       ClassDestructive,
			Scope:       ScopeAdmin,
			Twin:        "POST /api/signin/templates",
			Audit:       "signin.template",
			In:          &signInTemplateArgs{},
			ClassFor:    s.saveSignInTemplateClass,
			Typed:       argReader("id"),
			Consequences: func(ctx context.Context, args json.RawMessage) []string {
				var a signInTemplateArgs
				if json.Unmarshal(args, &a) != nil {
					return nil
				}
				var rule signin.Node
				if json.Unmarshal(a.Rule, &rule) != nil {
					return nil
				}
				sent := signin.Sentence(rule)
				if a.Create {
					return []string{"A new template " + q(a.ID) + " will be created: " + sent}
				}
				return []string{"Template " + q(a.ID) + " will be changed to: " + sent}
			},
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

		admin("set_sign_in_template_enabled", "Enable or disable a sign-in template.",
			ClassWrite, "PUT /api/signin/templates/{id}/enabled", "signin.template_enabled", func(ctx context.Context, a directory.Actor, in signInTemplateEnabledArgs) (any, error) {
				return s.setTemplateEnabled(ctx, a, in.ID, in.On)
			}),

		admin("delete_sign_in_template", "Delete a sign-in template.",
			ClassWrite, "DELETE /api/signin/templates/{id}", "signin.template_delete", func(ctx context.Context, a directory.Actor, in signInTemplateIDArgs) (any, error) {
				return nil, s.deleteTemplate(ctx, a, in.ID)
			}),

		{
			Name:        "preview_sign_in_template",
			Description: "Preview a sign-in template: its score, who it affects and who would be blocked.",
			Class:       ClassRead,
			Scope:       ScopeAdmin,
			Twin:        "POST /api/signin/templates/preview",
			Audit:       "",
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

		// set_default_template: D unless new Implies current.
		{
			Name:        "set_default_template",
			Description: "Set the Portcullis-wide default sign-in template (narrowing access needs your confirmation).",
			Class:       ClassDestructive,
			Scope:       ScopeAdmin,
			Twin:        "PUT /api/signin/default",
			Audit:       "signin.default",
			In:          &signInDefaultArgs{},
			ClassFor:    s.setDefaultTemplateClass,
			Typed:       argReader("template"),
			Consequences: func(ctx context.Context, args json.RawMessage) []string {
				var a signInDefaultArgs
				if json.Unmarshal(args, &a) != nil {
					return nil
				}
				return []string{"The default template will be " + q(a.Template)}
			},
			Run: func(ctx context.Context, c *directory.Caller, args json.RawMessage) (any, error) {
				in, err := decode[signInDefaultArgs](args)
				if err != nil {
					return nil, badArg("invalid arguments")
				}
				return s.setDefaultTemplate(ctx, toolActor(ctx, c), in.Template)
			},
		},

		// set_core_template: D unless new Implies current.
		{
			Name:        "set_core_template",
			Description: "Set a core page's sign-in template (narrowing access needs your confirmation).",
			Class:       ClassDestructive,
			Scope:       ScopeAdmin,
			Twin:        "PUT /api/signin/core/{key}",
			Audit:       "signin.core",
			In:          &signInCoreArgs{},
			ClassFor:    s.setCoreTemplateClass,
			Typed:       argReader("key"),
			Consequences: func(ctx context.Context, args json.RawMessage) []string {
				var a signInCoreArgs
				if json.Unmarshal(args, &a) != nil {
					return nil
				}
				name := a.Template
				if name == "" {
					name = "default"
				}
				return []string{"Core page " + q(a.Key) + " will use template " + q(name)}
			},
			Run: func(ctx context.Context, c *directory.Caller, args json.RawMessage) (any, error) {
				in, err := decode[signInCoreArgs](args)
				if err != nil {
					return nil, badArg("invalid arguments")
				}
				return s.setCoreTemplate(ctx, toolActor(ctx, c), in.Key, in.Template)
			},
		},

		// set_add_stronger: D when on, W when off.
		{
			Name:        "set_add_stronger",
			Description: "Let people register a stronger method than what they signed in with (turning this on needs your confirmation).",
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
					return []string{"People will be able to add any method"}
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
	signInAddStrongerArgs struct {
		On bool `json:"on" jsonschema:"true allows adding stronger methods, false restricts to the session's strength"`
	}
)

// ── ClassFor functions (per-call access control) ──

// setSignInMethodClass: D when on AND widening any in-use template, W when off.
func (s *Server) setSignInMethodClass(ctx context.Context, args json.RawMessage) ToolClass {
	var a signInMethodArgs
	if json.Unmarshal(args, &a) != nil {
		return ClassDestructive // fail closed
	}
	if !a.On {
		// Switching off: W
		return ClassWrite
	}

	// Switching ON: check if this widens any enabled template in use
	view, err := s.Hub.SignInView(ctx)
	if err != nil {
		return ClassDestructive // fail closed
	}

	// Build method sets: without and with this method
	withoutMethod := make(map[signin.Method]bool)
	withMethod := make(map[signin.Method]bool)
	for _, m := range view.Methods {
		if m.On {
			withoutMethod[m.ID] = true
			withMethod[m.ID] = true
		}
	}
	withMethod[a.Method] = true

	// Check each enabled template that's in use
	for _, t := range view.Templates {
		if !t.Enabled {
			continue
		}
		// Check if it's in use
		if len(t.UsedBy) == 0 {
			continue // not in use
		}

		// Compile this template without and with the method
		without, err := signin.Compile(t.Rule, withoutMethod)
		if err != nil {
			// Can't compile without: treat as not widening this one
			continue
		}
		with, err := signin.Compile(t.Rule, withMethod)
		if err != nil {
			// Can't compile with: fail closed
			return ClassDestructive
		}

		// If with doesn't imply without, this method switch-on widens this template
		if !signin.Implies(with, without) {
			return ClassDestructive
		}
	}

	// No template widened
	return ClassWrite
}

// saveSignInTemplateClass: D unless creating, or new Implies old under BOTH current switches and all available methods.
func (s *Server) saveSignInTemplateClass(ctx context.Context, args json.RawMessage) ToolClass {
	var a signInTemplateArgs
	if json.Unmarshal(args, &a) != nil {
		return ClassDestructive // fail closed
	}
	if a.Create {
		// Creating a new template: not D (it's a create operation)
		return ClassWrite
	}
	// Unmarshal the rule
	var newRule signin.Node
	if json.Unmarshal(a.Rule, &newRule) != nil {
		return ClassDestructive // fail closed
	}
	// Updating: check if new rule implies old rule
	view, err := s.Hub.SignInView(ctx)
	if err != nil {
		return ClassDestructive // fail closed
	}
	// Find the current template
	var oldRule *signin.Node
	for _, t := range view.Templates {
		if t.ID == a.ID {
			oldRule = &t.Rule
			break
		}
	}
	if oldRule == nil {
		return ClassDestructive // unknown template, fail closed
	}

	// Check 1: Compile with current switches
	currentOn := make(map[signin.Method]bool)
	for _, m := range view.Methods {
		if m.On {
			currentOn[m.ID] = true
		}
	}
	newCurrent, err := signin.Compile(newRule, currentOn)
	if err != nil {
		return ClassDestructive // can't compile new rule
	}
	oldCurrent, err := signin.Compile(*oldRule, currentOn)
	if err != nil {
		return ClassDestructive // can't compile old rule
	}
	if !signin.Implies(newCurrent, oldCurrent) {
		return ClassDestructive // widens under current switches
	}

	// Check 2: Compile with all available methods on
	allOn := make(map[signin.Method]bool)
	for _, m := range view.Methods {
		if m.Available { // all available methods, not just switched on
			allOn[m.ID] = true
		}
	}
	newAll, err := signin.Compile(newRule, allOn)
	if err != nil {
		return ClassDestructive // can't compile with all on
	}
	oldAll, err := signin.Compile(*oldRule, allOn)
	if err != nil {
		return ClassDestructive // can't compile old with all on
	}
	if !signin.Implies(newAll, oldAll) {
		return ClassDestructive // would widen if methods switched on
	}

	// Both checks passed: new implies old in both scenarios
	return ClassWrite
}

// setDefaultTemplateClass: D unless new Implies current.
func (s *Server) setDefaultTemplateClass(ctx context.Context, args json.RawMessage) ToolClass {
	var a signInDefaultArgs
	if json.Unmarshal(args, &a) != nil {
		return ClassDestructive // fail closed
	}
	view, err := s.Hub.SignInView(ctx)
	if err != nil {
		return ClassDestructive // fail closed
	}
	// Find the current default template's rule and the new template's rule
	var oldRule, newRule *signin.Node
	for _, t := range view.Templates {
		if t.ID == view.Default {
			oldRule = &t.Rule
		}
		if t.ID == a.Template {
			newRule = &t.Rule
		}
	}
	if oldRule == nil || newRule == nil {
		return ClassDestructive // fail closed
	}
	// Compile both rules with current methods
	on := make(map[signin.Method]bool)
	for _, m := range view.Methods {
		if m.On {
			on[m.ID] = true
		}
	}
	newCompiled, err := signin.Compile(*newRule, on)
	if err != nil {
		return ClassDestructive
	}
	oldCompiled, err := signin.Compile(*oldRule, on)
	if err != nil {
		return ClassDestructive
	}
	// If new implies old, it's not destructive
	if signin.Implies(newCompiled, oldCompiled) {
		return ClassWrite
	}
	return ClassDestructive
}

// setCoreTemplateClass: D unless new Implies current.
func (s *Server) setCoreTemplateClass(ctx context.Context, args json.RawMessage) ToolClass {
	var a signInCoreArgs
	if json.Unmarshal(args, &a) != nil {
		return ClassDestructive // fail closed
	}
	view, err := s.Hub.SignInView(ctx)
	if err != nil {
		return ClassDestructive // fail closed
	}
	// Find the current core template and the new template
	currentID := view.Core[a.Key]
	if currentID == "" {
		currentID = view.Default
	}
	newID := a.Template
	if newID == "" {
		newID = view.Default
	}
	var oldRule, newRule *signin.Node
	for _, t := range view.Templates {
		if t.ID == currentID {
			oldRule = &t.Rule
		}
		if t.ID == newID {
			newRule = &t.Rule
		}
	}
	if oldRule == nil || newRule == nil {
		return ClassDestructive // fail closed
	}
	// Compile both rules with current methods
	on := make(map[signin.Method]bool)
	for _, m := range view.Methods {
		if m.On {
			on[m.ID] = true
		}
	}
	newCompiled, err := signin.Compile(*newRule, on)
	if err != nil {
		return ClassDestructive
	}
	oldCompiled, err := signin.Compile(*oldRule, on)
	if err != nil {
		return ClassDestructive
	}
	// If new implies old, it's not destructive
	if signin.Implies(newCompiled, oldCompiled) {
		return ClassWrite
	}
	return ClassDestructive
}

// setAddStrongerClass: D when on, W when off.
func (s *Server) setAddStrongerClass(ctx context.Context, args json.RawMessage) ToolClass {
	var a signInAddStrongerArgs
	if json.Unmarshal(args, &a) != nil {
		return ClassDestructive // fail closed
	}
	if a.On {
		return ClassDestructive
	}
	return ClassWrite
}
