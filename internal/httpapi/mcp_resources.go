package httpapi

import (
	"context"
	"encoding/json"
	"io/fs"
	"log"
	"path"
	"slices"
	"strings"

	"github.com/portcullis/hub/internal/doctor"
	sdk "github.com/portcullis/hub/internal/mcpsdk"
)

// Read-only resources and prompts of the Portcullis MCP (contract
// §15.10): the docs pages the Hub ships (portcullis://docs/<name>, both
// scopes), each loaded template's manifest (portcullis://templates/<id>,
// generated values and secret defaults never included) with the list at
// portcullis://templates, and the doctor's check catalogue
// (portcullis://doctor/checks) — the last two and the prompts on the
// admin scope only. Every text goes through the tool redactor.

const (
	docsURIPrefix      = "portcullis://docs/"
	templatesURI       = "portcullis://templates"
	templateURIPrefix  = "portcullis://templates/"
	doctorChecksURI    = "portcullis://doctor/checks"
	mimeMarkdown       = "text/markdown"
	mimeJSON           = "application/json"
	templateURITmplate = "portcullis://templates/{id}"
)

// docPages are the embedded docs pages: name (the file's base name
// without .md) → path in s.Docs.
func (s *Server) docPages() map[string]string {
	out := map[string]string{}
	if s.Docs == nil {
		return out
	}
	files, _ := fs.Glob(s.Docs, "docs/*.md")
	for _, f := range files {
		out[strings.TrimSuffix(path.Base(f), ".md")] = f
	}
	return out
}

func (s *Server) addMCPResources(srv *sdk.Server, scope string) {
	pages := s.docPages()
	names := make([]string, 0, len(pages))
	for n := range pages {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		uri, file := docsURIPrefix+n, pages[n]
		srv.AddResource(&sdk.Resource{URI: uri, Name: n, Title: "Portcullis docs: " + n, MIMEType: mimeMarkdown},
			safeResource(uri, func(ctx context.Context, req *sdk.ReadResourceRequest) (*sdk.ReadResourceResult, error) {
				b, err := fs.ReadFile(s.Docs, file)
				if err != nil {
					return nil, sdk.ErrResourceNotFound(uri)
				}
				return sdk.TextResource(uri, mimeMarkdown, string(b)), nil
			}))
	}
	if scope != ScopeAdmin {
		return
	}
	srv.AddResource(&sdk.Resource{URI: templatesURI, Name: "templates", Title: "Loaded app templates", MIMEType: mimeJSON},
		safeResource(templatesURI, func(ctx context.Context, req *sdk.ReadResourceRequest) (*sdk.ReadResourceResult, error) {
			var list []map[string]string
			for _, t := range s.Hub.Templates() {
				list = append(list, map[string]string{"id": t.ID, "name": t.Manifest.Name, "uri": templateURIPrefix + t.ID})
			}
			return s.jsonResource(templatesURI, list)
		}))
	srv.AddResourceTemplate(&sdk.ResourceTemplate{URITemplate: templateURITmplate, Name: "template", Title: "An app template's manifest", MIMEType: mimeJSON},
		safeResource(templateURITmplate, func(ctx context.Context, req *sdk.ReadResourceRequest) (*sdk.ReadResourceResult, error) {
			uri := req.Params.URI
			id, ok := strings.CutPrefix(uri, templateURIPrefix)
			if !ok {
				return nil, sdk.ErrResourceNotFound(uri)
			}
			for _, t := range s.Hub.Templates() {
				if t.ID == id {
					m, err := manifestView(t.Manifest)
					if err != nil {
						return nil, err
					}
					return s.jsonResource(uri, map[string]any{"id": t.ID, "manifest": m})
				}
			}
			return nil, sdk.ErrResourceNotFound(uri)
		}))
	srv.AddResource(&sdk.Resource{URI: doctorChecksURI, Name: "doctor-checks", Title: "The doctor's check catalogue", MIMEType: mimeJSON},
		safeResource(doctorChecksURI, func(ctx context.Context, req *sdk.ReadResourceRequest) (*sdk.ReadResourceResult, error) {
			return s.jsonResource(doctorChecksURI, map[string]any{
				"kinds":      doctor.Kinds(),
				"documented": docsURIPrefix + "integration-contracts (§14.5, §14.6)",
			})
		}))
}

// jsonResource is v as JSON through the tool redactor (a set that can't
// be built hides the text).
func (s *Server) jsonResource(uri string, v any) (*sdk.ReadResourceResult, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	redact, err := s.toolRedactor()
	if err != nil {
		return sdk.TextResource(uri, "text/plain", textResultHidden), nil
	}
	return sdk.TextResource(uri, mimeJSON, clipResult(redact(string(b)))), nil
}

// manifestView is a manifest as JSON with every secret option's default
// and group values dropped (a manifest holds no generated value: those
// live in the instance's env file, never read here).
func manifestView(m any) (any, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	var walk func(any)
	walk = func(x any) {
		switch o := x.(type) {
		case map[string]any:
			if t, _ := o["type"].(string); t == "secret" || t == "person_secret" {
				delete(o, "default")
				delete(o, "group_values")
			}
			for _, c := range o {
				walk(c)
			}
		case []any:
			for _, c := range o {
				walk(c)
			}
		}
	}
	walk(v)
	return v, nil
}

// The prompts (admin scope).
var mcpPrompts = []struct {
	name, title, description string
	args                     [][2]string // name, description (all required)
	text                     string
}{
	{"diagnose_app", "Diagnose this app", "Find out why an app instance isn't working and what to do about it.",
		[][2]string{{"app", "the instance id, e.g. gitea"}},
		"Diagnose the Portcullis app instance {app}. Read its status, last operation, drift and doctor findings, and its recent logs. " +
			"Explain what is wrong in plain words and propose the fix. Don't change anything without asking me first; " +
			"destructive steps need my confirmation in the browser."},
	{"setup_app_for_team", "Set up an app for a team", "Install an app and give a group of people access to it.",
		[][2]string{{"app", "the template id, e.g. gitea"}, {"team", "the group whose members should use it"}},
		"Set up the Portcullis app {app} for the group {team}: check the template's manifest, create or enable the instance, " +
			"give {team} access through the instance's access group, and review its settings and access policy with me before saving."},
	{"why_cant_person_open_app", "Why can't <person> open <app>?", "Explain why a person can't use an app.",
		[][2]string{{"person", "the person's username"}, {"app", "the instance id"}},
		"Find out why {person} can't open the Portcullis app {app}: check that the app is enabled and healthy, its access policy and sign-in mode, " +
			"whether {person} is in its access group (and not expired), and their passkeys. Tell me the reason and the smallest fix."},
}

func (s *Server) addMCPPrompts(srv *sdk.Server, scope string) {
	if scope != ScopeAdmin {
		return
	}
	for _, p := range mcpPrompts {
		var args []*sdk.PromptArgument
		for _, a := range p.args {
			args = append(args, &sdk.PromptArgument{Name: a[0], Description: a[1], Required: true})
		}
		srv.AddPrompt(&sdk.Prompt{Name: p.name, Title: p.title, Description: p.description, Arguments: args},
			safePrompt(p.name, func(ctx context.Context, req *sdk.GetPromptRequest) (*sdk.GetPromptResult, error) {
				text := p.text
				for _, a := range p.args {
					v := strings.TrimSpace(req.Params.Arguments[a[0]])
					if v == "" {
						v = "<" + a[0] + ">"
					}
					text = strings.ReplaceAll(text, "{"+a[0]+"}", clipMessage(v, 200))
				}
				return sdk.UserPrompt(p.description, text), nil
			}))
	}
}

// safeResource / safePrompt recover a handler's panic (fix round 1): the
// log names the resource or prompt, never the value; the answer is the
// JSON-RPC error "internal error".
func safeResource(name string, h sdk.ResourceHandler) sdk.ResourceHandler {
	return func(ctx context.Context, req *sdk.ReadResourceRequest) (res *sdk.ReadResourceResult, err error) {
		defer func() {
			if recover() != nil {
				log.Printf("mcp: %s: panic", name)
				res, err = nil, sdk.InternalError()
			}
		}()
		return h(ctx, req)
	}
}

func safePrompt(name string, h sdk.PromptHandler) sdk.PromptHandler {
	return func(ctx context.Context, req *sdk.GetPromptRequest) (res *sdk.GetPromptResult, err error) {
		defer func() {
			if recover() != nil {
				log.Printf("mcp: %s: panic", name)
				res, err = nil, sdk.InternalError()
			}
		}()
		return h(ctx, req)
	}
}
