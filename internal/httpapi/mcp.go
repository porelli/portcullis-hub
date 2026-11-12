package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unicode/utf8"

	"github.com/portcullis/hub/internal/aigate"
	"github.com/portcullis/hub/internal/confirm"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/doctor"
	"github.com/portcullis/hub/internal/hub"
	sdk "github.com/portcullis/hub/internal/mcpsdk"
)

// The Portcullis MCP (contract §15.10; plan 4 Task 16): the Hub's own
// MCP server at /mcp/admin (https://hub.<d>/mcp, admins only) and
// /mcp/people (https://people.<d>/mcp, anyone signed in), on the MCP
// listener only (mcpRoute: the gate's secret and identity headers).
// Stateless Streamable HTTP through internal/mcpsdk (the one SDK
// adapter).
//
// Every tool is registered with registerTool and called through one path
// (callTool): the caller from mcpIdentity only (callerFrom = CallerFor +
// Via "ai" + Client) → /mcp/admin refuses non-admins ("admins only";
// audited refused for W and D) and /mcp/people tools with a Perm the
// caller lacks → argument names (G16: undeclared names, and on U tools
// every secret-looking name, are "secrets are never passed through the
// AI; use <url>") and the schema → class D: a confirmation (§15.6) → class
// U: the URL of the Hub's form → Run → toolResult (one global redactor,
// G40: redact, then clip to 1 MiB). Every answer is a tool result, never
// a protocol error and never HTTP 401/403.

// ToolClass is a Portcullis tool's class (§15.10).
type ToolClass string

const (
	ClassRead        ToolClass = "R" // read
	ClassWrite       ToolClass = "W" // write (audited)
	ClassDestructive ToolClass = "D" // needs a confirmation
	ClassSecret      ToolClass = "U" // needs a secret from the person: the URL of the Hub's form
)

// The two scopes (resources) of the Portcullis MCP.
const (
	ScopeAdmin  = "admin"
	ScopePeople = "people"
)

// Tool is one Portcullis MCP tool.
type Tool struct {
	Name, Description string
	Class             ToolClass
	Scope             string // ScopeAdmin | ScopePeople
	// Twin is the HTTP route it mirrors, exactly as registered
	// ("DELETE /api/directory/users/{username}", "/api/templates/enable").
	Twin string
	// AlsoTwins are further routes it mirrors (save_sign_in_template:
	// the create and the update route); the parity tests index each.
	AlsoTwins []string
	// Perm: people tools only, "" or a directory.Perm* the caller must
	// hold (hidden from callers without it, refused if called anyway).
	Perm string
	// Audit is the twin's audit action (W and D tools): a refusal before
	// Run (admins only, a missing permission) is audited refused under it.
	Audit string
	// In is the argument struct (its JSON schema, additionalProperties
	// false, is derived through the SDK adapter); Run gets the arguments'
	// canonical JSON (RFC 8785), which they were checked and confirmed as.
	In any
	// Typed is a D tool's typed check (the instance id, the person's or
	// group's name, the domain); "" = the tool's name.
	Typed func(args json.RawMessage) string
	// Consequences: D tools, the lines the page shows. ctx is the call's
	// (callTool's per-call memo: callMemo).
	Consequences func(ctx context.Context, args json.RawMessage) []string
	// ClassFor decides the class per call (G37: set_public_access on,
	// set_policy to a policy that isn't stricter, set_sign_in_mode to
	// native; doctor_apply_fix when its plan touches data): nil = Class.
	// A tool with one registers Class D (the strongest it can be: the
	// annotations, the parity rules and the D fields go by it) and
	// ClassFor answers ClassWrite or ClassDestructive for the call's
	// canonical arguments — anything else counts as D (fail closed); the
	// confirmation applies when it says D.
	ClassFor func(ctx context.Context, args json.RawMessage) ToolClass
	// SecretForm is a U tool's Hub URL of the form, pre-filled with
	// non-secret context. A U tool's Run runs only on a retry whose input
	// reply is "accept" — but that reply is the client's word, not the
	// person's: Run must read the server-side state (was the secret set,
	// when) and never treat the accept as proof that anything happened.
	SecretForm func(args json.RawMessage) string
	// Precheck (optional) runs after the arguments are checked and before
	// the class decision: an error is the tool's answer at once (audited
	// refused under Audit), so a call the twin would refuse never gets a
	// confirmation (delete_person on a guarded target). Run still makes
	// its own checks.
	Precheck func(ctx context.Context, c *directory.Caller, args json.RawMessage) error
	Run      func(ctx context.Context, c *directory.Caller, args json.RawMessage) (any, error)
}

// secretArgRe is the secret-looking argument name rule (§15.10).
var secretArgRe = regexp.MustCompile(`(?i)token|password|secret|key`)

// mcpSecretNameAllow are the declared argument names that may match
// secretArgRe, each with the reason it was allowed (G16; reviewed). A U
// tool takes none of them.
var mcpSecretNameAllow = map[string]string{
	"finding_token": "the doctor mute's finding digest (Finding.token): a digest of the finding's public inputs, not a credential",
	"key":           "a settings entry's option key (a manifest name such as api_url), never its value",
}

// mcpFreeFormAllow are the argument fields (tool.path) that may be a map,
// an interface or json.RawMessage — free-form JSON whose names no schema
// pins — each with the reason it was allowed (reviewed; none yet).
var mcpFreeFormAllow = map[string]string{}

var mcpToolNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// maxToolResult is a tool result's text bound, after redaction (§15.10).
const maxToolResult = 1 << 20

// The texts of §15.6 / §15.10.
const (
	textSecretArgs       = "secrets are never passed through the AI; use "
	textConfirmPrefix    = "This needs your confirmation in your browser: open "
	textConfirmSuffix    = ", then ask me to try again."
	textStillWaiting     = "Still waiting for your confirmation in your browser"
	textDeclined         = "You declined this in your browser"
	textCancelled        = "You cancelled the confirmation; nothing was done"
	textTooMany          = "Too many confirmations requested; try again later"
	textTooLong          = "these arguments are too long to confirm safely"
	textAdminsOnly       = "admins only"
	textNotAllowedPrefix = "not allowed: needs "
	textResultHidden     = "result hidden: secrets couldn't be read"
	textNoDirectory      = "Users & Groups is unavailable right now; try again"
	textInternal         = "internal error"
	textClipped          = "\n[clipped: the result is over 1 MiB]"
	confirmInputKey      = "portcullis_confirmation"
	secretFormInputKey   = "portcullis_secret_form"
)

// mcpTool is a registered tool with what registration derived.
type mcpTool struct {
	Tool
	schema   json.RawMessage
	props    map[string]bool
	validate func(any) error
	in       reflect.Type
}

// mcpState is the Server's Portcullis MCP state: the registry, the
// built SDK servers and the redactor cache.
type mcpState struct {
	mu      sync.Mutex
	tools   map[string][]*mcpTool // scope → tools in registration order
	gen     int
	servers map[string]mcpBuilt
	// registered: registerMCPTools ran (the real tools are registered once).
	registered bool

	redactMu  sync.Mutex
	redactKey string
	redactSet []string
	redactOK  bool
}

type mcpBuilt struct {
	gen int
	srv *sdk.Server
}

// checkTool is registration's check (registerTool panics on its error:
// a bad tool is a programming error, caught by the tests).
func checkTool(t Tool, existing []*mcpTool) (*mcpTool, error) {
	if !mcpToolNameRe.MatchString(t.Name) {
		return nil, fmt.Errorf("tool name %q", t.Name)
	}
	if t.Scope != ScopeAdmin && t.Scope != ScopePeople {
		return nil, fmt.Errorf("tool %s: scope %q", t.Name, t.Scope)
	}
	if slices.ContainsFunc(existing, func(x *mcpTool) bool { return x.Name == t.Name }) {
		return nil, fmt.Errorf("tool %s registered twice on %s", t.Name, t.Scope)
	}
	if strings.TrimSpace(t.Description) == "" || strings.TrimSpace(t.Twin) == "" || t.Run == nil || t.In == nil {
		return nil, fmt.Errorf("tool %s: description, twin, In and Run are required", t.Name)
	}
	switch t.Class {
	case ClassRead:
	case ClassWrite:
		if t.Audit == "" {
			return nil, fmt.Errorf("tool %s: a W tool names its audit action", t.Name)
		}
	case ClassDestructive:
		if t.Audit == "" || t.Typed == nil || t.Consequences == nil {
			return nil, fmt.Errorf("tool %s: a D tool needs Audit, Typed and Consequences", t.Name)
		}
	case ClassSecret:
		if t.SecretForm == nil {
			return nil, fmt.Errorf("tool %s: a U tool needs SecretForm", t.Name)
		}
	default:
		return nil, fmt.Errorf("tool %s: class %q", t.Name, t.Class)
	}
	if t.ClassFor != nil && t.Class != ClassDestructive {
		return nil, fmt.Errorf("tool %s: a tool with ClassFor registers class D (the strongest it can be)", t.Name)
	}
	if t.Perm != "" && (t.Scope != ScopePeople ||
		!slices.Contains([]string{directory.PermEditDetails, directory.PermInvite, directory.PermRemove, directory.PermSignInHelp}, t.Perm)) {
		return nil, fmt.Errorf("tool %s: perm %q (people tools only, a delegated permission)", t.Name, t.Perm)
	}
	in := reflect.TypeOf(t.In)
	for in.Kind() == reflect.Pointer {
		in = in.Elem()
	}
	if in.Kind() != reflect.Struct {
		return nil, fmt.Errorf("tool %s: In must be a struct", t.Name)
	}
	if err := checkArgType(t, in, "", map[reflect.Type]bool{}); err != nil {
		return nil, err
	}
	raw, props, validate, err := sdk.Schema(in)
	if err != nil {
		return nil, fmt.Errorf("tool %s: schema: %v", t.Name, err)
	}
	m := &mcpTool{Tool: t, schema: raw, props: map[string]bool{}, validate: validate, in: in}
	for _, p := range props {
		m.props[p] = true
	}
	return m, nil
}

var rawMessageType = reflect.TypeFor[json.RawMessage]()

// checkArgType walks an argument type (G16, fix round 1): every property
// name at any depth passes the secret-name rule (secretArgRe only from
// mcpSecretNameAllow, never on a U tool), and a map, an interface or
// json.RawMessage — names no schema pins — only from mcpFreeFormAllow.
func checkArgType(t Tool, ty reflect.Type, path string, seen map[reflect.Type]bool) error {
	for ty.Kind() == reflect.Pointer {
		ty = ty.Elem()
	}
	free := func() error {
		if mcpFreeFormAllow[t.Name+"."+path] == "" {
			return fmt.Errorf("tool %s: argument %s is free-form (%s) and isn't on the reviewed allowlist", t.Name, path, ty)
		}
		return nil
	}
	if ty == rawMessageType {
		return free()
	}
	switch ty.Kind() {
	case reflect.Map, reflect.Interface:
		return free()
	case reflect.Slice, reflect.Array:
		return checkArgType(t, ty.Elem(), path+"[]", seen)
	case reflect.Struct:
		if seen[ty] {
			return nil
		}
		seen[ty] = true
		defer delete(seen, ty)
		for i := 0; i < ty.NumField(); i++ {
			f := ty.Field(i)
			name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			if name == "-" || (!f.IsExported() && !f.Anonymous) {
				continue
			}
			if f.Anonymous && name == "" {
				if err := checkArgType(t, f.Type, path, seen); err != nil {
					return err
				}
				continue
			}
			if name == "" {
				name = f.Name
			}
			p := name
			if path != "" {
				p = path + "." + name
			}
			if secretArgRe.MatchString(name) {
				if t.Class == ClassSecret {
					return fmt.Errorf("tool %s: a U tool takes no secret-looking argument (%s)", t.Name, p)
				}
				if mcpSecretNameAllow[name] == "" {
					return fmt.Errorf("tool %s: argument %s looks like a secret and isn't on the reviewed allowlist", t.Name, p)
				}
			}
			if err := checkArgType(t, f.Type, p, seen); err != nil {
				return err
			}
		}
	}
	return nil
}

// registerTool adds t to its scope's registry (panics on a bad tool).
func (s *Server) registerTool(t Tool) {
	s.mcp.mu.Lock()
	defer s.mcp.mu.Unlock()
	m, err := checkTool(t, s.mcp.tools[t.Scope])
	if err != nil {
		panic("registerTool: " + err.Error())
	}
	if s.mcp.tools == nil {
		s.mcp.tools = map[string][]*mcpTool{}
	}
	s.mcp.tools[t.Scope] = append(s.mcp.tools[t.Scope], m)
	s.mcp.gen++
}

// tools are scope's registered tools, in registration order.
func (s *Server) tools(scope string) []Tool {
	s.mcp.mu.Lock()
	defer s.mcp.mu.Unlock()
	out := make([]Tool, 0, len(s.mcp.tools[scope]))
	for _, t := range s.mcp.tools[scope] {
		out = append(out, t.Tool)
	}
	return out
}

// registerMCPTools registers the real tools (Tasks 17–19), once per
// Server: the admin tools (mcptools_admin.go, mcptools_admin2.go,
// mcptools_directory.go, mcptools_doctor.go, mcptools_signin.go) and the people tools.
func (s *Server) registerMCPTools() {
	s.mcp.mu.Lock()
	done := s.mcp.registered
	s.mcp.registered = true
	s.mcp.mu.Unlock()
	if done {
		return
	}
	s.registerAdminTools()
	s.registerAdminTools2()
	s.registerDirectoryTools()
	s.registerDoctorTools()
	s.registerSignInTools()
	s.registerPeopleTools()
	s.registerMySignInTools()
	s.registerSignInHelpTools()
	s.registerImpersonationTools()
}

// mcpScopeOf names the scope's resource URL, listener, page base and
// label for the person's messages.
type mcpScopeInfo struct {
	resource, listener, home, label string
}

func (s *Server) mcpScope(scope string) mcpScopeInfo {
	d := hub.NormalizeHost(s.Hub.Domain())
	if scope == ScopeAdmin {
		return mcpScopeInfo{aigate.AdminURL(d), confirm.ListenerHub, "https://hub." + d + "/", "Portcullis (admin)"}
	}
	return mcpScopeInfo{aigate.PeopleURL(d), confirm.ListenerPeople, "https://people." + d + "/", "Portcullis"}
}

var errNoMCPIdentity = errors.New("no AI identity")

// callerFrom is the tool caller: the MCP listener's identity only
// (mcpIdentity, put on the request by mcpRoute; G41) resolved with
// CallerFor and given Via "ai" and the AI client (Service.CallerAs).
func (s *Server) callerFrom(ctx context.Context) (*directory.Caller, error) {
	a, ok := ctx.Value(mcpIdentityKey{}).(directory.Actor)
	if !ok || a.Via != directory.ViaAI || a.Client == "" {
		return nil, errNoMCPIdentity
	}
	if s.Directory == nil {
		return nil, errors.New("user management not configured")
	}
	return s.Directory.CallerAs(ctx, a)
}

// mcpHandler is the Streamable HTTP handler of scope's server.
func (s *Server) mcpHandler(scope string) http.HandlerFunc {
	h := sdk.Handler(func(*http.Request) *sdk.Server { return s.mcpServer(scope) })
	return h.ServeHTTP
}

// mcpServer is scope's SDK server, rebuilt when the registry changed.
func (s *Server) mcpServer(scope string) *sdk.Server {
	s.mcp.mu.Lock()
	defer s.mcp.mu.Unlock()
	if b, ok := s.mcp.servers[scope]; ok && b.gen == s.mcp.gen {
		return b.srv
	}
	info := s.mcpScope(scope)
	srv := sdk.NewServer("portcullis-hub", info.label)
	for _, t := range s.mcp.tools[scope] {
		srv.AddTool(&sdk.Tool{Name: t.Name, Description: t.Description, InputSchema: t.schema, Annotations: annotations(t.Class, t.Twin)},
			s.toolHandler(scope, t))
	}
	srv.AddReceivingMiddleware(sdk.FilterTools(func(ctx context.Context) func(string) bool {
		return s.mcpVisible(ctx, scope)
	}))
	if scope == ScopeAdmin {
		// Admins only, for every method (fix round 1): non-admins get
		// empty lists, "admins only" for reads and prompts; tools/call
		// reaches callTool, which refuses and audits.
		srv.AddReceivingMiddleware(sdk.AdminOnly(func(ctx context.Context) (bool, error) {
			c, err := s.callerFrom(ctx)
			if err != nil {
				log.Printf("mcp: admin: resolve caller: %v", err)
				return false, err
			}
			return c.Admin, nil
		}, textNoDirectory))
	}
	s.addMCPResources(srv, scope)
	s.addMCPPrompts(srv, scope)
	if s.mcp.servers == nil {
		s.mcp.servers = map[string]mcpBuilt{}
	}
	s.mcp.servers[scope] = mcpBuilt{gen: s.mcp.gen, srv: srv}
	return srv
}

// annotations (§15.10): R readOnlyHint; D destructiveHint; W and U
// destructiveHint false; idempotentHint where the twin is a PUT.
func annotations(c ToolClass, twin string) *sdk.ToolAnnotations {
	t, f := true, false
	a := &sdk.ToolAnnotations{IdempotentHint: strings.HasPrefix(twin, "PUT ")}
	switch c {
	case ClassRead:
		a.ReadOnlyHint = true
	case ClassDestructive:
		a.DestructiveHint = &t
	default:
		a.DestructiveHint = &f
	}
	return a
}

// mcpVisible is tools/list's filter for the request's caller: a people
// tool with a Perm is listed only to holders (and admins); a caller that
// can't be resolved sees no such tool.
func (s *Server) mcpVisible(ctx context.Context, scope string) func(string) bool {
	s.mcp.mu.Lock()
	perms := map[string]string{}
	for _, t := range s.mcp.tools[scope] {
		perms[t.Name] = t.Perm
	}
	s.mcp.mu.Unlock()
	var c *directory.Caller
	resolved := false
	return func(name string) bool {
		p := perms[name]
		if p == "" {
			return true
		}
		if !resolved {
			c, _ = s.callerFrom(ctx)
			resolved = true
		}
		return c != nil && (c.Admin || c.Perms[p])
	}
}

func (s *Server) toolHandler(scope string, t *mcpTool) sdk.ToolHandler {
	return func(ctx context.Context, req *sdk.CallToolRequest) (res *sdk.CallToolResult, err error) {
		defer func() {
			if recover() != nil {
				// The value is never formatted: it may hold anything.
				log.Printf("mcp: %s: panic", t.Name)
				res, err = sdk.TextResult(textInternal, true), nil
			}
		}()
		return s.callTool(ctx, scope, t, sdk.CallOf(req)), nil
	}
}

type confirmationKey struct{}

// confirmationID is the id of the confirmation the running D tool
// consumed ("" for other tools): its own audit entry carries
// "confirmation <id>" in its detail (§15.6).
func confirmationID(ctx context.Context) string {
	id, _ := ctx.Value(confirmationKey{}).(string)
	return id
}

// callTool is the one call path of every tool.
func (s *Server) callTool(ctx context.Context, scope string, t *mcpTool, call sdk.Call) *sdk.CallToolResult {
	info := s.mcpScope(scope)
	c, err := s.callerFrom(ctx)
	if err != nil {
		var de *directory.Error
		if errors.As(err, &de) && de.Status < 500 {
			return s.errResult(de.Msg)
		}
		log.Printf("mcp: %s: resolve caller: %v", t.Name, err)
		return sdk.TextResult(textNoDirectory, true)
	}
	switch {
	case scope == ScopeAdmin && !c.Admin:
		s.auditToolRefusal(c, t, textAdminsOnly)
		return sdk.TextResult(textAdminsOnly, true)
	case t.Perm != "" && !c.Admin && !c.Perms[t.Perm]:
		// The twin's own refusal (directory: 403 "not allowed: needs
		// <perm>"), status-prefixed like every tool error.
		why := textNotAllowedPrefix + t.Perm
		s.auditToolRefusal(c, t, why)
		return sdk.TextResult("403: "+why, true)
	}
	ctx = withCallMemo(ctx, c)
	args, declared, refusal := checkArgs(t, call.Arguments)
	if refusal != "" {
		url := info.home
		if t.Class == ClassSecret {
			url = t.SecretForm(declared)
		}
		if refusal == refusalSecret {
			return sdk.TextResult(textSecretArgs+url, true)
		}
		return s.errResult(refusal)
	}
	precheck := t.Precheck
	if t.Consequences != nil {
		// A tool that may ask for a confirmation: names the page would
		// show are checked first (final review M3).
		own := t.Precheck
		precheck = func(ctx context.Context, c *directory.Caller, args json.RawMessage) error {
			if err := s.checkNameArgs(ctx, t.Name, t.In, args); err != nil {
				return err
			}
			if t.Typed != nil {
				if typed := strings.TrimSpace(t.Typed(args)); typed != "" && !s.validTyped(ctx, typed) {
					return badArg("the confirmation's typed check " + q(clipMessage(typed, 64)) + " is not a valid name")
				}
			}
			if own != nil {
				return own(ctx, c, args)
			}
			return nil
		}
	}
	if precheck != nil {
		if err := precheck(ctx, c, args); err != nil {
			redact, rerr := s.toolRedactor()
			if rerr != nil {
				log.Printf("mcp: %s: redaction set: %v", t.Name, rerr)
				return sdk.TextResult(textResultHidden, true)
			}
			res := toolError(err, redact)
			s.auditToolRefusal(c, t, sdk.TextOf(res))
			return res
		}
	}
	class := t.Class
	if t.ClassFor != nil {
		if class = t.ClassFor(ctx, args); class != ClassWrite {
			class = ClassDestructive
		}
	}
	switch class {
	case ClassDestructive:
		id, answer := s.confirmCall(ctx, c, t, info, args, call)
		if answer != nil {
			return answer
		}
		ctx = context.WithValue(ctx, confirmationKey{}, id)
	case ClassSecret:
		switch call.InputReply(secretFormInputKey) {
		case "accept":
		case "decline", "cancel":
			return sdk.TextResult("You cancelled; nothing was done", true)
		default:
			url := t.SecretForm(args)
			if call.Protocol == sdk.ProtocolStateless && call.URLElicit {
				if r, err := sdk.URLInputRequired(secretFormInputKey, t.Name+" on "+info.label+" needs a secret from you: enter it in your browser.", url, ""); err == nil {
					return r
				}
			}
			return sdk.TextResult("This needs a secret, which is never passed through the AI: enter it in your browser at "+url+", then ask me to check.", true)
		}
	}
	v, err := t.Run(ctx, c, args)
	// The redactor is built after Run: a secret Run itself set is in it.
	redact, rerr := s.toolRedactor()
	if rerr != nil {
		log.Printf("mcp: %s: redaction set: %v", t.Name, rerr)
		return sdk.TextResult(textResultHidden, true)
	}
	if err != nil {
		return toolError(err, redact)
	}
	return toolResult(v, redact)
}

// auditToolRefusal records a refusal before Run of a tool with an audit
// action (every W and D tool; a delegate U tool such as invite_person)
// under its twin's action, attributed via ai and the client.
func (s *Server) auditToolRefusal(c *directory.Caller, t *mcpTool, why string) {
	if t.Audit == "" || s.Audit == nil {
		return
	}
	a := c.Actor()
	if err := s.Audit.Append(directory.AuditEntry{Actor: a.User, Via: a.Via, Client: a.Client, Action: t.Audit,
		Target: t.Name, Detail: "tool " + t.Name + ": " + why, Result: "refused"}); err != nil {
		log.Printf("audit: %v", err)
	}
}

const refusalSecret = "\x00secret"

// checkArgs: the arguments (absent or null = {}) as their canonical JSON
// (sdk.CanonicalArguments: the gate's canon rules), every top-level name
// declared (undeclared, or a secret-looking name on a U tool =
// refusalSecret), valid against the schema and decodable into In.
// declared is the object with only the declared names (for SecretForm).
func checkArgs(t *mcpTool, raw json.RawMessage) (args, declared json.RawMessage, refusal string) {
	declared = json.RawMessage("{}")
	r := strings.TrimSpace(string(raw))
	if r == "" || r == "null" {
		r = "{}"
	}
	if r[0] != '{' || !utf8.ValidString(r) {
		return nil, declared, "invalid arguments: not one JSON object"
	}
	canon, err := sdk.CanonicalArguments(json.RawMessage(r))
	if err != nil {
		return nil, declared, "invalid arguments: they can't be passed on unchanged (one JSON object, distinct keys, safe numbers, depth ≤ 64)"
	}
	var m map[string]any
	if err := json.Unmarshal(canon, &m); err != nil {
		return nil, declared, "invalid arguments: not one JSON object"
	}
	keep := map[string]any{}
	secret := false
	for k, v := range m {
		if !t.props[k] || (t.Class == ClassSecret && secretArgRe.MatchString(k)) {
			secret = true
			continue
		}
		keep[k] = v
	}
	if b, err := json.Marshal(keep); err == nil {
		if c, err := sdk.CanonicalArguments(b); err == nil {
			declared = c
		}
	}
	if secret {
		return nil, declared, refusalSecret
	}
	if err := t.validate(m); err != nil {
		return nil, declared, "invalid arguments: " + err.Error()
	}
	dec := json.NewDecoder(strings.NewReader(string(canon)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(reflect.New(t.in).Interface()); err != nil {
		return nil, declared, "invalid arguments: " + err.Error()
	}
	return canon, declared, ""
}

// confirmCall (§15.6): a D tool runs only by consuming an approved
// confirmation of exactly (person, resource, tool, sha256 of args) on
// the scope's listener → its id. Otherwise the answer: still waiting,
// declined, or a new confirmation — a 2026-07-28 client that declared
// URL elicitation gets an InputRequiredResult with the page's URL
// elicitation, every other client the text (the Hub's MCP is stateless:
// no elicitation/create; G17). Never form mode, never 401/403.
func (s *Server) confirmCall(ctx context.Context, c *directory.Caller, t *mcpTool, info mcpScopeInfo, args json.RawMessage, call sdk.Call) (string, *sdk.CallToolResult) {
	sum := sha256.Sum256(args)
	digest := hex.EncodeToString(sum[:])
	conf, err := s.Hub.ConsumeConfirmation(info.listener, c.User, info.resource, t.Name, digest)
	switch {
	case err == nil:
		return conf.ID, nil
	case errors.Is(err, confirm.ErrPending):
		if r := call.InputReply(confirmInputKey); r == "decline" || r == "cancel" {
			return "", sdk.TextResult(textCancelled, true)
		}
		return "", sdk.TextResult(textStillWaiting, true)
	case errors.Is(err, confirm.ErrDeclined):
		return "", sdk.TextResult(textDeclined, true)
	case !errors.Is(err, confirm.ErrNotFound):
		return "", s.errResult("can't check the confirmation right now; try again")
	}
	if len(args) > 4<<10 {
		return "", sdk.TextResult(textTooLong, true)
	}
	// Everything the page shows is made visible here, once (security
	// review of the final fix; hub.VisibleText: bidi, zero-width, format
	// and control characters as \uXXXX). Argument values reach the
	// consequence lines only as validated names (checkNameArgs) or quoted
	// through q(); the typed check passed validTyped in the Precheck.
	typed := strings.TrimSpace(t.Typed(args))
	if typed == "" {
		typed = t.Name
	}
	cons := t.Consequences(ctx, args)
	for i := range cons {
		cons[i] = hub.VisibleText(cons[i])
	}
	conf, err = s.Hub.CreateConfirmation(c.Actor(), confirm.Request{
		User: c.User, Client: c.Client, Resource: info.resource, Tool: t.Name, ArgsSHA256: digest, ArgsPreview: string(args),
		Listener: info.listener, Typed: typed, Label: typed + " on " + hub.VisibleText(info.label), Consequences: cons,
	})
	if err != nil {
		var se *hub.StatusError
		if errors.As(err, &se) && se.Status == http.StatusTooManyRequests {
			return "", sdk.TextResult(textTooMany, true)
		}
		log.Printf("mcp: %s: create confirmation: %v", t.Name, err)
		return "", s.errResult("can't ask for a confirmation right now; try again")
	}
	url := s.Hub.ConfirmationURL(conf)
	if call.Protocol == sdk.ProtocolStateless && call.URLElicit {
		if r, err := sdk.URLInputRequired(confirmInputKey, t.Name+" on "+info.label+" needs your confirmation in your browser.", url, conf.ID); err == nil {
			return "", r
		}
	}
	return "", sdk.TextResult(textConfirmPrefix+url+textConfirmSuffix, true)
}

// errResult is an isError result of a message that holds no secret
// (refusals the Hub words itself), clipped.
func (s *Server) errResult(msg string) *sdk.CallToolResult {
	return sdk.TextResult(clipMessage(msg, 2000), true)
}

// toolError maps a Run error as the HTTP handlers do (writeErr): the
// status first ("409: …"; errStatus with 500 as the default, a
// directory error's own), then an OpError as its JSON record, anything
// else (a 409 busy included) its message — always an isError result,
// redacted, then clipped.
func toolError(err error, redact func(string) string) *sdk.CallToolResult {
	code := errStatus(err, http.StatusInternalServerError)
	var de *directory.Error
	if errors.As(err, &de) {
		code = de.Status
	}
	prefix := strconv.Itoa(code) + ": "
	if rec := opRecordOf(err); rec != nil {
		// A busy instance's running record, a refused Stop's record
		// (§15.10): "409: <record JSON>".
		b, _ := json.Marshal(rec)
		return sdk.TextResult(prefix+clipResult(redact(string(b))), true)
	}
	var oe *hub.OpError
	if errors.As(err, &oe) {
		b, _ := json.Marshal(map[string]any{"error": oe.Record.Error, "op": oe.Record.Op, "output": oe.Record.Output,
			"hint": oe.Record.Hint, "rolled_back": oe.Record.RolledBack})
		return sdk.TextResult(prefix+clipResult(redact(string(b))), true)
	}
	msg := err.Error()
	if de != nil {
		msg = de.Msg
	}
	return sdk.TextResult(prefix+clipMessage(redact(msg), 2000), true)
}

// toolResult is v as JSON text, redacted, then clipped to 1 MiB.
func toolResult(v any, redact func(string) string) *sdk.CallToolResult {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return sdk.TextResult("the result can't be encoded", true)
	}
	return sdk.TextResult(clipResult(redact(strings.TrimSuffix(b.String(), "\n"))), false)
}

// clipResult bounds a redacted text to maxToolResult bytes (with the
// note), on a rune boundary.
func clipResult(s string) string {
	if len(s) <= maxToolResult {
		return s
	}
	n := maxToolResult - len(textClipped)
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + textClipped
}

// OpStarted is a long operation's answer (§15.10): the twin's 202 body,
// at once; get_op / wait_for_op show the outcome.
type OpStarted struct {
	OpID     string `json:"op_id"`
	Op       string `json:"op"`
	Instance string `json:"instance"`
	Poll     string `json:"poll"`
}

// inviteLinkRe: core's invite links (§9.4, https://enroll.<d>/invite/<token>)
// never reach the model (§15.10).
var inviteLinkRe = regexp.MustCompile(`(?i)https?://enroll\.[^/\s"'<>\\]+/invite/[^\s"'<>\\]+`)

// toolRedactor is the one redactor of every tool result (G40): the union
// of every instance's redaction set and the provider secrets
// (Hub.ToolRedactionSet), the Hub's file secrets (proxy and MCP gate
// secrets, RedactFiles: the invite and domains secrets, the LLDAP
// password; RedactLiterals: the Keycloak admin password) and invite links. The set is cached under a key of every
// source's stat (Hub.ToolRedactionKey + RedactFiles), rebuilt when it
// changes. err: a source exists but can't be read — the result is hidden.
func (s *Server) toolRedactor() (func(string) string, error) {
	key := s.Hub.ToolRedactionKey() + "\x00" + filesKey(s.RedactFiles)
	st := &s.mcp
	st.redactMu.Lock()
	defer st.redactMu.Unlock()
	if !st.redactOK || st.redactKey != key {
		vals, err := s.Hub.ToolRedactionSet()
		if err != nil {
			st.redactOK = false
			return nil, err
		}
		for _, p := range s.RedactFiles {
			b, err := os.ReadFile(p)
			switch {
			case errors.Is(err, os.ErrNotExist):
				continue
			case err != nil:
				st.redactOK = false
				return nil, fmt.Errorf("a Hub secret file can't be read: %v", errors.Unwrap(err))
			}
			if v := strings.TrimSpace(string(b)); v != "" {
				vals = append(vals, v)
			}
			clear(b)
		}
		st.redactKey, st.redactSet, st.redactOK = key, vals, true
	}
	// The values the Hub holds in memory are added on every call (never
	// part of the cached set, so a change of them can't go stale).
	vals := slices.Clone(st.redactSet)
	for _, v := range append([]string{s.Secret, s.MCPSecret}, s.RedactLiterals...) {
		if v != "" {
			vals = append(vals, v)
		}
	}
	return func(x string) string {
		return inviteLinkRe.ReplaceAllString(hub.RedactValues(x, vals), "[invite link hidden]")
	}, nil
}

// filesKey is a stat line per file — size, mtime, inode — never the
// content (a file replaced by rename changes its inode).
func filesKey(paths []string) string {
	var b strings.Builder
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil {
			fmt.Fprintf(&b, "%s:%v\n", p, errors.Is(err, os.ErrNotExist))
			continue
		}
		var ino uint64
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			ino = uint64(st.Ino)
		}
		fmt.Fprintf(&b, "%s:%d:%d:%d\n", p, fi.Size(), fi.ModTime().UnixNano(), ino)
	}
	return b.String()
}

type callMemoKey struct{}

// callMemo is one tools/call's shared state (T18 fix round 1): the
// caller, and the directory's Membership read once for the call's class,
// consequences and Run (dirGuards).
type callMemo struct {
	c    *directory.Caller
	once sync.Once
	m    *directory.Membership
	// The doctor's report, run once for the call's class and
	// consequences (Task 20 fix round 1: doctorReport).
	docOnce sync.Once
	doc     *doctor.Report
	docErr  error
	// stop_op: the op id of the record its class judged ("" none), so
	// Run stops only that one (stopExpected, Hub.StopOpExpect).
	stopOnce sync.Once
	stopOpID string
}

func withCallMemo(ctx context.Context, c *directory.Caller) context.Context {
	return context.WithValue(ctx, callMemoKey{}, &callMemo{c: c})
}

func memoOf(ctx context.Context) *callMemo {
	m, _ := ctx.Value(callMemoKey{}).(*callMemo)
	return m
}

// noCtx adapts a consequences function that needs no call state.
func noCtx(f func(json.RawMessage) []string) func(context.Context, json.RawMessage) []string {
	return func(_ context.Context, args json.RawMessage) []string { return f(args) }
}
