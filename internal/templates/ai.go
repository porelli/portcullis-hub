package templates

import (
	"fmt"
	"maps"
	"net/url"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/portcullis/hub/internal/policy"
	"gopkg.in/yaml.v3"
)

// The manifest's ai: block (contract §3.2): every template says whether
// the AI can act in the app (ai.mcp companions) or why not
// (ai.unsupported). ValidateAI implements exactly the contract's
// refusals, like the templates repo's tests/validate.py.

// AI is the manifest's ai: block.
type AI struct {
	MCP         []Companion  `yaml:"mcp" json:"mcp,omitempty"`
	Unsupported string       `yaml:"unsupported" json:"unsupported,omitempty"`
	Alternative *Alternative `yaml:"alternative" json:"alternative,omitempty"`
	OnChange    string       `yaml:"on_change" json:"on_change,omitempty"`
	Chat        *Chat        `yaml:"chat" json:"chat,omitempty"`

	// present: the keys the block wrote (an empty unsupported or mcp
	// list is refused, not taken for absent).
	present map[string]bool
}

// UnmarshalYAML decodes strictly (unknown keys are refused).
func (a *AI) UnmarshalYAML(n *yaml.Node) error {
	type plain AI
	if err := strictDecode(n, (*plain)(a)); err != nil {
		return fmt.Errorf("ai: %v", err)
	}
	a.present = map[string]bool{}
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			a.present[n.Content[i].Value] = true
		}
	}
	return nil
}

// Companion is one ai.mcp[] entry: an MCP server the AI talks to.
type Companion struct {
	Name        string      `yaml:"name" json:"name"`
	Label       string      `yaml:"label" json:"label"`
	Kind        string      `yaml:"kind" json:"kind"`
	Service     string      `yaml:"service" json:"service"`
	Port        int         `yaml:"port" json:"port,omitempty"`
	Path        string      `yaml:"path" json:"path,omitempty"`
	Router      string      `yaml:"router" json:"router"`
	PublicPath  string      `yaml:"public_path" json:"public_path,omitempty"`
	Identity    Identity    `yaml:"identity" json:"identity"`
	Modes       []string    `yaml:"modes" json:"modes"`
	DefaultMode string      `yaml:"default_mode" json:"default_mode,omitempty"`
	Tools       ToolClasses `yaml:"tools" json:"tools"`
	Aggregate   *bool       `yaml:"aggregate" json:"aggregate,omitempty"`
	Upstream    string      `yaml:"upstream" json:"upstream"`
	Source      string      `yaml:"source" json:"source"`
	Protocol    []string    `yaml:"protocol" json:"protocol"`
}

// UnmarshalYAML decodes strictly.
func (c *Companion) UnmarshalYAML(n *yaml.Node) error {
	type plain Companion
	return strictDecode(n, (*plain)(c))
}

// Identity is a companion's identity mode and that mode's parameters.
type Identity struct {
	Mode         string              `yaml:"mode" json:"mode"`
	Header       string              `yaml:"header" json:"header,omitempty"`
	Format       string              `yaml:"format" json:"format,omitempty"`
	Basic        *BasicFormat        `yaml:"basic" json:"basic,omitempty"`
	Mint         string              `yaml:"mint" json:"mint,omitempty"`
	Revoke       string              `yaml:"revoke" json:"revoke,omitempty"`
	Scopes       map[string][]string `yaml:"scopes" json:"scopes,omitempty"`
	CallerSecret *CallerSecret       `yaml:"caller_secret" json:"caller_secret,omitempty"`
}

// UnmarshalYAML decodes strictly.
func (i *Identity) UnmarshalYAML(n *yaml.Node) error {
	type plain Identity
	return strictDecode(n, (*plain)(i))
}

// BasicFormat is app_token's HTTP Basic form.
type BasicFormat struct {
	User     string `yaml:"user" json:"user"`
	Password string `yaml:"password" json:"password"`
}

// CallerSecret is identity_headers' secret the companion requires.
type CallerSecret struct {
	Env    string `yaml:"env" json:"env"`
	Header string `yaml:"header" json:"header,omitempty"`
	Format string `yaml:"format" json:"format,omitempty"`
}

// ToolClasses are a companion's tool patterns (§15.5).
type ToolClasses struct {
	Writes  []string `yaml:"writes" json:"writes"`
	Confirm []string `yaml:"confirm" json:"confirm"`
	Never   []string `yaml:"never" json:"never"`
}

// Alternative is a community server the admin may evaluate on their own
// (only displayed, never installed).
type Alternative struct {
	Name   string `yaml:"name" json:"name"`
	Source string `yaml:"source" json:"source"`
	Note   string `yaml:"note" json:"note"`
}

// Chat is ai.chat: the template is an AI page (an MCP client).
type Chat struct {
	ProviderKinds map[string]string `yaml:"provider_kinds" json:"provider_kinds"`
	File          ChatFile          `yaml:"file" json:"file"`
	// Env is the one service whose environment gets the selected
	// providers' secret variables (G31).
	Env ChatEnv `yaml:"env" json:"env"`
}

// ChatFile is where ai-providers.json is mounted read-only.
type ChatFile struct {
	Service string `yaml:"service" json:"service"`
	Mount   string `yaml:"mount" json:"mount"`
}

// ChatEnv names the service receiving the provider variables.
type ChatEnv struct {
	Service string `yaml:"service" json:"service"`
}

// Contract values.
const (
	AIReadOnly  = "read_only"
	AIReadWrite = "read_write"

	IdentityAppToken = "app_token"
	IdentityHeaders  = "identity_headers"
	IdentityAppOAuth = "app_oauth"

	CompanionKind = "companion"
	BuiltinKind   = "builtin"

	UpstreamOfficial  = "official"
	UpstreamCommunity = "community"

	// MCPNamePrefix starts the Hub's companion aliases and routers
	// (portcullis-mcp-<instance-id>--<companion>); reserved in templates.
	MCPNamePrefix = "portcullis-mcp-"
	// AIClientPrefix starts the Hub's AI Keycloak clients.
	AIClientPrefix = "portcullis-ai-"
	// AIProvidersFile is the reserved data file of an AI page.
	AIProvidersFile = "ai-providers"
	// DefaultMCPPath is path's and public_path's default.
	DefaultMCPPath = "/mcp"
	// MaxAliasLen: the alias is one DNS label.
	MaxAliasLen = 63
)

// MCPProtocols are the MCP versions a companion may declare.
var MCPProtocols = []string{"2025-06-18", "2025-11-25", "2026-07-28"}

// ProviderKinds are the model provider kinds ai.chat may render.
var ProviderKinds = []string{"litellm", "openai_compatible", "anthropic", "openai", "google", "bedrock", "azure_openai"}

// Aggregated reports whether the companion's tools are in "all my apps":
// never for app_oauth, else aggregate (default true).
func (c Companion) Aggregated() bool {
	if c.Identity.Mode == IdentityAppOAuth {
		return false
	}
	return c.Aggregate == nil || *c.Aggregate
}

// EffectivePath is the upstream's MCP path (default /mcp).
func (c Companion) EffectivePath() string {
	if c.Path == "" {
		return DefaultMCPPath
	}
	return c.Path
}

// EffectivePublicPath is the path people connect to on the router's
// host: public_path (default /mcp); for app_oauth the app's own route,
// path.
func (c Companion) EffectivePublicPath() string {
	if c.Identity.Mode == IdentityAppOAuth {
		return c.EffectivePath()
	}
	if c.PublicPath == "" {
		return DefaultMCPPath
	}
	return c.PublicPath
}

// MCPAlias is the companion's alias and router name for instance id.
func MCPAlias(id, companion string) string { return MCPNamePrefix + id + "--" + companion }

// AliasFits reports whether MCPAlias(id, companion) is one DNS label.
func AliasFits(id, companion string) bool {
	return len(MCPNamePrefix)+len(id)+2+len(companion) <= MaxAliasLen
}

var (
	companionNameRe = regexp.MustCompile(`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`)
	tokenFormatRe   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,31} \{credential\}$`)
	secretFormatRe  = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,31} \{secret\}$`)
	aiHeaderRe      = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
	toolPatternRe   = regexp.MustCompile(`^[A-Za-z0-9_.*-]{1,128}(:[A-Za-z0-9_.*-]{1,128})?$`)
	// mcpPathRe: absolute, segments of URL-safe characters (no ?, #,
	// spaces, %); path.Clean is checked too.
	mcpPathRe = regexp.MustCompile(`^/([A-Za-z0-9._~-]+(/[A-Za-z0-9._~-]+)*)?$`)
)

// Companion limits.
const (
	companionNameMax  = 31
	companionLabelMax = 64
	unsupportedMax    = 200
	altNameMax        = 64
	altNoteMax        = 200
	toolPatternsMax   = 256
	scopeMax          = 128
)

// forbiddenHeaders may never carry a companion credential (folded).
var (
	// A superset of mcp-gate's forbiddenHeader (core
	// mcp-gate/internal/config/config.go): a name the gate refuses would
	// make it refuse the whole mcp-gate.json.
	forbiddenHeaders = set("host", "cookie", "content-type", "accept", "proxy-authorization", "mcp-protocol-version", "mcp-session-id",
		"content-length", "transfer-encoding", "connection", "te", "upgrade", "keep-alive", "trailer", "proxy-connection")
	forbiddenHeaderPrefixes = []string{"mcp-", "x-forwarded-", "x-auth-request-", "remote-", "x-portcullis-"}
)

// singleLine: 1–max runes, no control characters, not blank.
func singleLine(s string, max int) bool {
	return strings.TrimSpace(s) != "" && utf8.RuneCountInString(s) <= max && !HasControlChars(s)
}

// httpsURL: an absolute https URL with a host and no userinfo.
func httpsURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && !HasControlChars(s) && !strings.ContainsAny(s, " \t")
}

// validMCPPath: absolute, clean, no ? / #.
func validMCPPath(p string) bool { return mcpPathRe.MatchString(p) && path.Clean(p) == p }

func checkAIHeader(where, h string) error {
	low := strings.ToLower(h)
	if !aiHeaderRe.MatchString(h) || forbiddenHeaders[low] {
		return fmt.Errorf("%s %q must match %s and not be Host, Cookie, Content-Type, Accept, Content-Length, Transfer-Encoding, Connection, TE, Upgrade, Keep-Alive, Trailer, Proxy-Connection, Proxy-Authorization, Mcp-*, MCP-Protocol-Version, Mcp-Session-Id, X-Forwarded-*, X-Auth-Request-*, Remote-* or X-Portcullis-*", where, h, aiHeaderRe)
	}
	for _, p := range forbiddenHeaderPrefixes {
		if strings.HasPrefix(low, p) {
			return fmt.Errorf("%s %q may not start with %s (the gate's and core's headers)", where, h, p)
		}
	}
	return nil
}

// ValidateAI checks the manifest's ai: block against the manifest, the
// compose file and the routes (contract §3.2). Discover calls it after
// ValidateSettingsSpec (hooks are validated by then).
func ValidateAI(t *Template, compose []byte, routes *Routes) error {
	m := &t.Manifest
	for _, c := range m.Clients {
		if strings.HasPrefix(strings.ToLower(c.ClientID), AIClientPrefix) {
			return fmt.Errorf("keycloak_clients: client_id %s: the prefix %s is the Hub's AI clients' (contract §8)", c.ClientID, AIClientPrefix)
		}
	}
	for _, f := range m.Files {
		if f.Name == AIProvidersFile {
			return fmt.Errorf("files[%s]: the data file name %s is reserved for the AI page (contract §3.2)", f.Name, AIProvidersFile)
		}
	}
	core := policy.CoreSubdomains()
	for _, sub := range t.Subdomains {
		if core[sub] {
			return fmt.Errorf("default subdomain %s is a core host (contract §4): choose another", sub)
		}
	}
	a := m.AI
	if a == nil {
		return fmt.Errorf("ai: required (ai.mcp or ai.unsupported)")
	}
	hasMCP, hasUnsup := a.present["mcp"], a.present["unsupported"]
	switch {
	case hasMCP && hasUnsup:
		return fmt.Errorf("ai: either ai.mcp or ai.unsupported, not both")
	case !hasMCP && !hasUnsup:
		return fmt.Errorf("ai: required (ai.mcp or ai.unsupported)")
	}
	if hasUnsup {
		if !singleLine(a.Unsupported, unsupportedMax) {
			return fmt.Errorf("ai.unsupported must be one line of 1–%d characters", unsupportedMax)
		}
		if a.OnChange != "" {
			return fmt.Errorf("ai.on_change is only allowed with ai.mcp")
		}
		if alt := a.Alternative; alt != nil {
			switch {
			case !singleLine(alt.Name, altNameMax):
				return fmt.Errorf("ai.alternative.name must be one line of 1–%d characters", altNameMax)
			case !httpsURL(alt.Source):
				return fmt.Errorf("ai.alternative.source must be an https:// URL")
			case !singleLine(alt.Note, altNoteMax):
				return fmt.Errorf("ai.alternative.note must be one line of 1–%d characters", altNoteMax)
			}
		}
	} else {
		if len(a.MCP) == 0 {
			return fmt.Errorf("ai.mcp: list at least one companion (or use ai.unsupported)")
		}
		if a.Alternative != nil {
			return fmt.Errorf("ai.alternative is only allowed with ai.unsupported")
		}
		if a.Chat != nil {
			return fmt.Errorf("ai.chat is only allowed with ai.unsupported (an AI page is no app the AI drives)")
		}
	}
	if err := checkAIClients(t, compose); err != nil {
		return err
	}
	named := map[string]bool{} // hooks the block names
	if hasMCP {
		if err := checkCompanions(t, compose, routes, named); err != nil {
			return err
		}
		if a.OnChange != "" {
			if err := aiHook(m, "ai.on_change", a.OnChange); err != nil {
				return err
			}
			named[a.OnChange] = true
		}
	}
	if err := checkAIVarRefs(m, compose); err != nil {
		return err
	}
	for _, h := range m.Hooks {
		if h.IsAI() && !named[h.Name] {
			return fmt.Errorf("hooks[%s]: when: [ai] but no ai: field names it (only ai.mcp[].identity.mint / revoke and ai.on_change run ai hooks)", h.Name)
		}
	}
	// An ai hook never runs on a kind: companion service: that service is
	// at scale 0 while its companion is off, so the revoke_all owed before
	// a switch-on (and the on_change after a switch-off) could never run.
	companionSvc := map[string]bool{}
	for _, c := range a.MCP {
		if c.Kind == CompanionKind {
			companionSvc[c.Service] = true
		}
	}
	for _, h := range m.Hooks {
		if named[h.Name] && companionSvc[h.Service] {
			return fmt.Errorf("hooks[%s]: an ai hook may not run on service %s: it backs a kind: companion companion, at scale 0 while AI support is off (run it on the app's own service)", h.Name, h.Service)
		}
	}
	return nil
}

// aiHook: hook name exists and is exactly when: [ai].
func aiHook(m *Manifest, where, name string) error {
	for _, h := range m.Hooks {
		if h.Name == name {
			if len(h.When) != 1 || h.When[0] != HookAI {
				return fmt.Errorf("%s: hook %s must have exactly when: [ai] (contract §13.8)", where, name)
			}
			return nil
		}
	}
	return fmt.Errorf("%s: hook %s is not declared in hooks", where, name)
}

// checkAIClients: ai_client entries only with ai.chat, exactly one
// there, confidential; ai.chat's fields.
func checkAIClients(t *Template, compose []byte) error {
	m := &t.Manifest
	var aiClients []KeycloakClient
	for _, c := range m.Clients {
		if c.AIClient {
			aiClients = append(aiClients, c)
		}
	}
	ch := m.AI.Chat
	if ch == nil {
		if len(aiClients) > 0 {
			return fmt.Errorf("keycloak_clients: client %s has ai_client: true, which is only allowed with ai.chat", aiClients[0].ClientID)
		}
		return nil
	}
	if len(aiClients) != 1 {
		return fmt.Errorf("ai.chat: exactly one keycloak_clients entry has ai_client: true (found %d)", len(aiClients))
	}
	if aiClients[0].SecretEnv == "" {
		return fmt.Errorf("keycloak_clients: ai_client %s needs a secret_env (a confidential client)", aiClients[0].ClientID)
	}
	if len(ch.ProviderKinds) == 0 {
		return fmt.Errorf("ai.chat.provider_kinds: list at least one model provider kind (%s)", strings.Join(ProviderKinds, ", "))
	}
	for k, n := range ch.ProviderKinds {
		if !slices.Contains(ProviderKinds, k) {
			return fmt.Errorf("ai.chat.provider_kinds: %q must be one of %s", k, strings.Join(ProviderKinds, ", "))
		}
		if n != "one" && n != "many" {
			return fmt.Errorf("ai.chat.provider_kinds: %s: %q must be one or many", k, n)
		}
	}
	services := map[string]bool{}
	for _, s := range Services(compose) {
		services[s] = true
	}
	if !services[ch.File.Service] {
		return fmt.Errorf("ai.chat.file: service %q is not in compose.yml", ch.File.Service)
	}
	if !validMount(ch.File.Mount) {
		return fmt.Errorf("ai.chat.file: mount %q must be an absolute, clean container directory (no ':')", ch.File.Mount)
	}
	for _, f := range m.Files {
		if f.Service == ch.File.Service && nested(f.Mount, ch.File.Mount) {
			return fmt.Errorf("ai.chat.file: mount %s collides with files[%s]'s mount %s", ch.File.Mount, f.Name, f.Mount)
		}
	}
	if ch.Env.Service == "" || !services[ch.Env.Service] {
		return fmt.Errorf("ai.chat.env: service %q must be a service of compose.yml (it receives the providers' variables)", ch.Env.Service)
	}
	return nil
}

// checkAIVarRefs: compose reads PORTCULLIS_AI_ENABLED only as exactly
// ${PORTCULLIS_AI_ENABLED:-false} and PORTCULLIS_AI_READONLY_<C> only as
// exactly ${PORTCULLIS_AI_READONLY_<C>:-true} for one of its own
// companions (only templates with ai.mcp), never PORTCULLIS_AI_PROVIDER_*
// nor any other PORTCULLIS_AI_* name.
func checkAIVarRefs(m *Manifest, compose []byte) error {
	var doc interface{}
	if err := yaml.Unmarshal(compose, &doc); err != nil {
		return fmt.Errorf("compose.yml: %v", err)
	}
	var scalars []string
	scalarValues(doc, &scalars)
	own := map[string]bool{}
	for _, c := range m.AI.MCP {
		own[ReadOnlyVar(c.Name)] = true
	}
	mcp := len(m.AI.MCP) > 0
	for _, s := range scalars {
		for _, r := range rawVarRefs(s) {
			// A default or alternate text naming an AI variable (${X:-PORTCULLIS_AI_…},
			// any case) could build one (fix round 1, security review).
			if rest := r.text[min(len(r.text), 1+len(r.name)+1):]; strings.HasPrefix(r.text, "${") && strings.Contains(strings.ToUpper(rest), varAIPrefix) {
				return fmt.Errorf("compose.yml: %s: a default or alternate value naming %s* is refused (the AI variables are the Hub's)", r.text, varAIPrefix)
			}
			if !strings.HasPrefix(r.name, varAIPrefix) {
				continue
			}
			switch {
			case strings.HasPrefix(r.name, varAIProviderPref):
				return fmt.Errorf("compose.yml references %s: PORTCULLIS_AI_PROVIDER_* variables are never referenced by a template (the Hub adds them to ai.chat.env's service)", r.name)
			case r.name == VarAIEnabled:
				if !mcp || r.text != "${"+VarAIEnabled+":-false}" {
					return fmt.Errorf("compose.yml: %s may appear only as exactly ${%s:-false}, in a template with ai.mcp", VarAIEnabled, VarAIEnabled)
				}
			case own[r.name]:
				if r.text != "${"+r.name+":-true}" {
					return fmt.Errorf("compose.yml: %s may appear only as exactly ${%s:-true}", r.name, r.name)
				}
			default:
				return fmt.Errorf("compose.yml references %s: the only AI variables are %s and PORTCULLIS_AI_READONLY_<COMPANION> of the template's own companions", r.name, VarAIEnabled)
			}
		}
	}
	// Nor may a service set one (an environment map key, or a list item
	// NAME / NAME=…; case-insensitive): it would take the Hub's provider
	// secret's place (G31, Task 23 fix round 1).
	for _, svc := range sortedMapKeys(mapping(mapping(doc)["services"])) {
		for _, k := range environmentKeys(mapping(mapping(doc)["services"])[svc]) {
			if strings.Contains(k, "$") {
				return fmt.Errorf("compose.yml: service %s: the environment variable name %q is built by interpolation: names are written out", svc, k)
			}
			if strings.HasPrefix(strings.ToUpper(k), varAIProviderPref) {
				return fmt.Errorf("compose.yml: service %s sets %s: PORTCULLIS_AI_PROVIDER_* variables are set only by the Hub (on ai.chat.env's service)", svc, k)
			}
		}
	}
	return nil
}

// mapping is v as a string-keyed map (nil: not one).
func mapping(v interface{}) map[string]interface{} {
	m, _ := v.(map[string]interface{})
	return m
}

func sortedMapKeys(m map[string]interface{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// environmentKeys are the variable names a compose service's environment
// sets: its map keys, or each list item's name (before the first =).
func environmentKeys(svc interface{}) []string {
	var out []string
	switch env := mapping(svc)["environment"].(type) {
	case map[string]interface{}:
		out = append(out, sortedMapKeys(env)...)
	case []interface{}:
		for _, it := range env {
			if s, ok := it.(string); ok {
				name, _, _ := strings.Cut(s, "=")
				out = append(out, strings.TrimSpace(name))
			}
		}
	}
	return out
}

// rawRef is a compose interpolation with its full text.
type rawRef struct{ name, text string }

// rawVarRefs are the interpolations of s ($$ is a literal $) with their
// text: ${…} up to its closing brace, or $NAME.
func rawVarRefs(s string) []rawRef {
	var out []rawRef
	for i := 0; i < len(s); i++ {
		if s[i] != '$' {
			continue
		}
		if i+1 < len(s) && s[i+1] == '$' {
			i++
			continue
		}
		j := i + 1
		braced := j < len(s) && s[j] == '{'
		if braced {
			j++
		}
		k := j
		for k < len(s) && (s[k] == '_' || s[k] >= 'A' && s[k] <= 'Z' || s[k] >= 'a' && s[k] <= 'z' || s[k] >= '0' && s[k] <= '9') {
			k++
		}
		if k == j {
			continue
		}
		end := k
		if braced {
			if c := strings.IndexByte(s[k:], '}'); c >= 0 {
				end = k + c + 1
			} else {
				end = len(s)
			}
		}
		out = append(out, rawRef{name: s[j:k], text: s[i:end]})
	}
	return out
}

// composeServiceInfo is what the companion rules read of a service.
type composeServiceInfo struct {
	networks    []string
	networkMode bool
	netModeOf   string // network_mode's value when a string
	pidOf       string // pid's value when a string
	ipcOf       string // ipc's value when a string
	// hasPid, hasIpc, hasVolumesFrom: the key is set (any value);
	// volumesFrom: its string entries.
	hasPid, hasIpc, hasVolumesFrom bool
	volumesFrom                    []string
	ports                          bool     // ports: declared (published to the host)
	named                          []string // container_name / hostname present
	image                          string   // image: as written ("" = none or not a string)
	// capDrop, capAdd: the lists as written; privileged: present and
	// neither false nor "false"; deviceKey: devices or
	// device_cgroup_rules, the first present ("" = neither).
	capDrop, capAdd []string
	privileged      bool
	deviceKey       string
}

func composeServiceInfos(compose []byte) map[string]composeServiceInfo {
	var doc struct {
		Services map[string]map[string]interface{} `yaml:"services"`
	}
	out := map[string]composeServiceInfo{}
	if yaml.Unmarshal(compose, &doc) != nil {
		return out
	}
	for name, s := range doc.Services {
		var info composeServiceInfo
		switch n := s["networks"].(type) {
		case []interface{}:
			for _, x := range n {
				if v, ok := x.(string); ok {
					info.networks = append(info.networks, v)
				}
			}
		case map[string]interface{}:
			for k := range n {
				info.networks = append(info.networks, k)
			}
		}
		_, info.networkMode = s["network_mode"]
		info.netModeOf, _ = s["network_mode"].(string)
		info.pidOf, _ = s["pid"].(string)
		info.ipcOf, _ = s["ipc"].(string)
		_, info.hasPid = s["pid"]
		_, info.hasIpc = s["ipc"]
		_, info.hasVolumesFrom = s["volumes_from"]
		if l, ok := s["volumes_from"].([]interface{}); ok {
			for _, x := range l {
				if v, ok := x.(string); ok {
					info.volumesFrom = append(info.volumesFrom, v)
				}
			}
		}
		_, info.ports = s["ports"]
		info.image, _ = s["image"].(string)
		strs := func(v interface{}) []string {
			var out []string
			switch l := v.(type) {
			case []interface{}:
				for _, x := range l {
					out = append(out, fmt.Sprint(x))
				}
			case nil:
			default:
				out = append(out, fmt.Sprint(l))
			}
			return out
		}
		info.capDrop, info.capAdd = strs(s["cap_drop"]), strs(s["cap_add"])
		if p, ok := s["privileged"]; ok && p != false && p != "false" {
			info.privileged = true
		}
		for _, k := range []string{"devices", "device_cgroup_rules"} {
			if _, ok := s[k]; ok && info.deviceKey == "" {
				info.deviceKey = k
			}
		}
		for _, f := range []string{"container_name", "hostname"} {
			if _, ok := s[f]; ok {
				info.named = append(info.named, f)
			}
		}
		sort.Strings(info.networks)
		out[name] = info
	}
	return out
}

// checkCompanions applies the ai.mcp rules; named collects the hooks
// the companions name.
func checkCompanions(t *Template, compose []byte, routes *Routes, named map[string]bool) error {
	m := &t.Manifest
	a := &m.Auth
	if len(a.AdminPaths) > 0 {
		return fmt.Errorf("ai.mcp: not allowed with auth.admin_paths (the gate can't apply path groups; use ai.unsupported)")
	}
	if a.Method == "public" || a.Method == "mtls" {
		return fmt.Errorf("ai.mcp: not allowed with auth.method %s (no Portcullis identity, or LoA 3)", a.Method)
	}
	if m.Routerless() || routes == nil || len(routes.Info) == 0 {
		return fmt.Errorf("ai.mcp: not allowed on a router-less template (a companion's endpoint is on one of its hosts)")
	}
	services := map[string]bool{}
	for _, s := range Services(compose) {
		services[s] = true
	}
	infos := composeServiceInfos(compose)
	randomEnv := map[string]bool{}
	for _, e := range m.Env {
		if e.Generate == "random" {
			randomEnv[e.Key] = true
		}
	}
	var publicPrefixes []string
	if pa := a.PublicAccess; pa != nil {
		for _, p := range pa.Paths {
			pre, _, _ := strings.Cut(p.Prefix, "{token}")
			if pre = strings.TrimRight(pre, "/"); pre == "" {
				pre = "/"
			}
			publicPrefixes = append(publicPrefixes, pre)
		}
	}
	names := map[string]bool{}
	serviceUse := map[string]string{} // service → companion
	type routedPath struct{ path, name string }
	publicPaths := map[string][]routedPath{} // router → endpoint paths
	for i := range m.AI.MCP {
		c := &m.AI.MCP[i]
		w := fmt.Sprintf("ai.mcp[%s]", c.Name)
		if !companionNameRe.MatchString(c.Name) || len(c.Name) > companionNameMax {
			return fmt.Errorf("ai.mcp[%d]: name %q must match %s and be at most %d characters", i, c.Name, companionNameRe, companionNameMax)
		}
		if names[c.Name] {
			return fmt.Errorf("%s: name declared twice", w)
		}
		names[c.Name] = true
		if !AliasFits(t.ID, c.Name) {
			return fmt.Errorf("%s: the alias %s is longer than %d characters (one DNS label: 15 + len(id) + 2 + len(companion) ≤ %d)", w, MCPAlias(t.ID, c.Name), MaxAliasLen, MaxAliasLen)
		}
		if !singleLine(c.Label, companionLabelMax) {
			return fmt.Errorf("%s: label must be one line of 1–%d characters", w, companionLabelMax)
		}
		if c.Kind != CompanionKind && c.Kind != BuiltinKind {
			return fmt.Errorf("%s: kind %q must be companion or builtin", w, c.Kind)
		}
		if !services[c.Service] {
			return fmt.Errorf("%s: service %s is not in compose.yml", w, c.Service)
		}
		if !idNormalRe.MatchString(c.Service) {
			return fmt.Errorf("%s: service %s must match %s (no _, no --, no trailing -)", w, c.Service, idNormalRe)
		}
		mode := c.Identity.Mode
		if mode != IdentityAppToken && mode != IdentityHeaders && mode != IdentityAppOAuth {
			return fmt.Errorf("%s: identity.mode %q must be app_token, identity_headers or app_oauth", w, mode)
		}
		if mode == IdentityAppOAuth && c.Kind != BuiltinKind {
			return fmt.Errorf("%s: app_oauth needs kind builtin (the app is its own MCP authorization server)", w)
		}
		if o, ok := serviceUse[c.Service]; ok && (c.Kind == CompanionKind || kindOf(m, o) == CompanionKind) {
			return fmt.Errorf("%s: companion service %s already backs companion %s", w, c.Service, o)
		}
		if c.Kind == CompanionKind {
			if routes.TraefikLabelled[c.Service] {
				return fmt.Errorf("%s: companion service %s may have no traefik.* label (the Hub routes it)", w, c.Service)
			}
			info := infos[c.Service]
			if slices.Contains(info.networks, proxyNetwork) {
				return fmt.Errorf("%s: companion service %s may not join %s itself (the Hub's override attaches it while AI support is on)", w, c.Service, proxyNetwork)
			}
			if info.networkMode {
				return fmt.Errorf("%s: companion service %s may not set network_mode", w, c.Service)
			}
			if len(info.named) > 0 {
				return fmt.Errorf("%s: companion service %s may not set %s", w, c.Service, strings.Join(info.named, " or "))
			}
			if info.ports {
				return fmt.Errorf("%s: companion service %s may not publish ports (the gate is the only way in)", w, c.Service)
			}
			// A service sharing the companion's network namespace would
			// reach it (and be reached) past the gate.
			for _, name := range slices.Sorted(maps.Keys(infos)) {
				if infos[name].netModeOf == "service:"+c.Service {
					return fmt.Errorf("%s: service %s uses network_mode service:%s, the companion service's network namespace (it would reach the companion past the gate)", w, name, c.Service)
				}
			}
		}
		if c.Kind == CompanionKind && mode == IdentityHeaders {
			if err := checkTrustNetwork(w, c, compose, infos, routes); err != nil {
				return err
			}
		}
		if mode == IdentityHeaders {
			// A host-network service sends from the host's addresses, the
			// trust network's gateway side included.
			for _, name := range slices.Sorted(maps.Keys(infos)) {
				if infos[name].netModeOf == "host" {
					return fmt.Errorf("%s: service %s uses network_mode host: not allowed next to an identity_headers companion (it reaches the app from the host's addresses)", w, name)
				}
				if infos[name].pidOf == "host" {
					return fmt.Errorf("%s: service %s uses pid host: not allowed next to an identity_headers companion (it sees every process of the host, the companion's included)", w, name)
				}
			}
			if err := checkCallerSecretScope(w, c, compose); err != nil {
				return err
			}
		}
		serviceUse[c.Service] = c.Name
		if (mode != IdentityAppOAuth && c.Port < 1) || c.Port < 0 || c.Port > 65535 {
			return fmt.Errorf("%s: port %d must be 1–65535", w, c.Port)
		}
		if c.Path != "" && !validMCPPath(c.Path) {
			return fmt.Errorf("%s: path %q must be absolute and clean, without ? or #", w, c.Path)
		}
		if _, ok := routes.HostRouters[c.Router]; !ok {
			return fmt.Errorf("%s: router %q is not a host router of the template (a router whose rule is Host() alone)", w, c.Router)
		}
		if mode == IdentityAppOAuth && c.PublicPath != "" {
			return fmt.Errorf("%s: public_path is refused on an app_oauth companion (its endpoint is the app's own route https://<host><path>)", w)
		}
		// The endpoint path on the router's host: public_path, or an
		// app_oauth companion's own path; no two companions share one.
		pp := c.EffectivePublicPath()
		if mode != IdentityAppOAuth {
			if err := checkPublicPath(w, pp, publicPrefixes); err != nil {
				return err
			}
		}
		for _, o := range publicPaths[c.Router] {
			if nested(pp, o.path) {
				return fmt.Errorf("%s: endpoint path (public_path, or path for app_oauth) %s on router %s overlaps companion %s's %s", w, pp, c.Router, o.name, o.path)
			}
		}
		publicPaths[c.Router] = append(publicPaths[c.Router], routedPath{pp, c.Name})
		if err := checkModes(w, c); err != nil {
			return err
		}
		if err := checkIdentity(w, m, c, randomEnv, named); err != nil {
			return err
		}
		for _, l := range []struct {
			n string
			p []string
		}{{"writes", c.Tools.Writes}, {"confirm", c.Tools.Confirm}, {"never", c.Tools.Never}} {
			if len(l.p) > toolPatternsMax {
				return fmt.Errorf("%s: tools.%s lists more than %d patterns", w, l.n, toolPatternsMax)
			}
			for _, p := range l.p {
				if !toolPatternRe.MatchString(p) {
					return fmt.Errorf("%s: tools.%s pattern %q must match %s", w, l.n, p, toolPatternRe)
				}
			}
		}
		if mode == IdentityAppOAuth && c.Aggregate != nil && *c.Aggregate {
			return fmt.Errorf("%s: aggregate: true is refused on an app_oauth companion (never in \"all my apps\")", w)
		}
		switch c.Upstream {
		case UpstreamOfficial:
		case UpstreamCommunity:
			if c.Kind == BuiltinKind {
				return fmt.Errorf("%s: upstream community with kind builtin (the app's own server is official)", w)
			}
		default:
			return fmt.Errorf("%s: upstream %q must be official or community", w, c.Upstream)
		}
		if !httpsURL(c.Source) {
			return fmt.Errorf("%s: source must be an https:// URL (the companion project's home)", w)
		}
		if len(c.Protocol) == 0 {
			return fmt.Errorf("%s: protocol must list at least one of %s", w, strings.Join(MCPProtocols, ", "))
		}
		seen := map[string]bool{}
		for _, p := range c.Protocol {
			if !slices.Contains(MCPProtocols, p) || seen[p] {
				return fmt.Errorf("%s: protocol %q must be one of %s, each once", w, p, strings.Join(MCPProtocols, ", "))
			}
			seen[p] = true
		}
	}
	return nil
}

// kindOf is companion name's kind.
func kindOf(m *Manifest, name string) string {
	for _, c := range m.AI.MCP {
		if c.Name == name {
			return c.Kind
		}
	}
	return ""
}

// checkPublicPath: absolute, clean, not /, not at or under /.well-known/
// or /oauth2/, and clear of the template's public_access paths (at,
// under or above one: either way the public router and the MCP route
// would share paths).
func checkPublicPath(w, pp string, publicPrefixes []string) error {
	if !validMCPPath(pp) || pp == "/" {
		return fmt.Errorf("%s: public_path %q must be absolute and clean, and not /", w, pp)
	}
	for _, r := range []string{"/.well-known", "/oauth2"} {
		if pp == r || strings.HasPrefix(pp, r+"/") {
			return fmt.Errorf("%s: public_path %s may not be at or under %s/ (metadata and sign-in routes)", w, pp, r)
		}
	}
	for _, p := range publicPrefixes {
		if p == "/" || nested(pp, p) {
			return fmt.Errorf("%s: public_path %s overlaps the auth.public_access path %s", w, pp, p)
		}
	}
	return nil
}

func checkModes(w string, c *Companion) error {
	if len(c.Modes) == 0 {
		return fmt.Errorf("%s: modes must list read_only and/or read_write", w)
	}
	seen := map[string]bool{}
	for _, md := range c.Modes {
		if (md != AIReadOnly && md != AIReadWrite) || seen[md] {
			return fmt.Errorf("%s: modes must be a subset of read_only, read_write without repeats (got %v)", w, c.Modes)
		}
		seen[md] = true
	}
	if c.Identity.Mode == IdentityAppOAuth && (len(c.Modes) != 1 || c.Modes[0] != AIReadWrite) {
		return fmt.Errorf("%s: an app_oauth companion's modes are exactly [read_write]", w)
	}
	if c.DefaultMode != "" && !seen[c.DefaultMode] {
		return fmt.Errorf("%s: default_mode %q is not one of modes %v", w, c.DefaultMode, c.Modes)
	}
	if len(c.Modes) == 2 && c.DefaultMode == "" {
		return fmt.Errorf("%s: default_mode is required when modes has two entries", w)
	}
	return nil
}

func checkIdentity(w string, m *Manifest, c *Companion, randomEnv, named map[string]bool) error {
	id := &c.Identity
	// Only the mode's own parameters (any other key is refused).
	extra := func(fields ...struct {
		n  string
		on bool
	}) error {
		for _, f := range fields {
			if f.on {
				return fmt.Errorf("%s: identity.%s is not a parameter of mode %s", w, f.n, id.Mode)
			}
		}
		return nil
	}
	type fu = struct {
		n  string
		on bool
	}
	switch id.Mode {
	case IdentityAppToken:
		if err := extra(fu{"caller_secret", id.CallerSecret != nil}); err != nil {
			return err
		}
		if id.Header != "" {
			if err := checkAIHeader(w+": identity.header", id.Header); err != nil {
				return err
			}
		}
		switch {
		case id.Format != "" && id.Basic != nil:
			return fmt.Errorf("%s: identity: exactly one of format and basic, not both", w)
		case id.Format != "":
			if !tokenFormatRe.MatchString(id.Format) {
				return fmt.Errorf("%s: identity.format %q must match %s (e.g. \"token {credential}\")", w, id.Format, tokenFormatRe)
			}
		case id.Basic != nil:
			u := id.Basic.User
			if u != "{username}" && (!singleLine(u, 128) || strings.ContainsAny(u, ":{}")) {
				return fmt.Errorf("%s: identity.basic.user must be exactly {username} or a one-line literal without :, { or }", w)
			}
			if id.Basic.Password != "{credential}" {
				return fmt.Errorf("%s: identity.basic.password must be exactly {credential}", w)
			}
		default:
			return fmt.Errorf("%s: identity: app_token needs format or basic", w)
		}
		if id.Mint == "" {
			return fmt.Errorf("%s: identity.mint (a hook) is required for app_token", w)
		}
		if id.Revoke == "" {
			return fmt.Errorf("%s: identity.revoke (a hook) is required for app_token", w)
		}
		for k, scopes := range id.Scopes {
			if !slices.Contains(c.Modes, k) {
				return fmt.Errorf("%s: identity.scopes key %q is not one of modes %v", w, k, c.Modes)
			}
			for _, s := range scopes {
				if !singleLine(s, scopeMax) {
					return fmt.Errorf("%s: identity.scopes.%s entries must be one line of 1–%d characters", w, k, scopeMax)
				}
			}
		}
	case IdentityHeaders:
		if err := extra(fu{"header", id.Header != ""}, fu{"format", id.Format != ""}, fu{"basic", id.Basic != nil},
			fu{"mint", id.Mint != ""}, fu{"revoke", id.Revoke != ""}, fu{"scopes", id.Scopes != nil}); err != nil {
			return err
		}
		cs := id.CallerSecret
		if cs == nil {
			return fmt.Errorf("%s: identity_headers needs identity.caller_secret {env, header, format}", w)
		}
		if !randomEnv[cs.Env] {
			return fmt.Errorf("%s: identity.caller_secret.env %q must be an env entry with generate: random", w, cs.Env)
		}
		if cs.Header != "" {
			if err := checkAIHeader(w+": identity.caller_secret.header", cs.Header); err != nil {
				return err
			}
		}
		if f := cs.Format; f != "" && f != "{secret}" && !secretFormatRe.MatchString(f) {
			return fmt.Errorf("%s: identity.caller_secret.format %q must contain {secret} once: exactly {secret} or match %s", w, f, secretFormatRe)
		}
	case IdentityAppOAuth:
		if err := extra(fu{"header", id.Header != ""}, fu{"format", id.Format != ""}, fu{"basic", id.Basic != nil},
			fu{"mint", id.Mint != ""}, fu{"scopes", id.Scopes != nil}, fu{"caller_secret", id.CallerSecret != nil}); err != nil {
			return err
		}
		if id.Revoke == "" {
			return fmt.Errorf("%s: identity.revoke (a hook) is required for app_oauth", w)
		}
	}
	for _, h := range []struct{ f, n string }{{"identity.mint", id.Mint}, {"identity.revoke", id.Revoke}} {
		if h.n == "" {
			continue
		}
		if err := aiHook(m, w+": "+h.f, h.n); err != nil {
			return err
		}
		named[h.n] = true
	}
	return nil
}

// ServiceNetworks reports, per compose service, the networks it declares
// (nil: none, so it is on the project's default network) and whether it
// sets network_mode (the Hub's override adds a companion's alias only to
// a service that can join networks).
func ServiceNetworks(compose []byte) map[string]ServiceNet {
	out := map[string]ServiceNet{}
	for name, i := range composeServiceInfos(compose) {
		out[name] = ServiceNet{Networks: i.networks, NetworkMode: i.networkMode}
	}
	return out
}

// ServiceImages is, per compose service, its image: as written ("" when
// it has none, e.g. a build-only service).
func ServiceImages(compose []byte) map[string]string {
	out := map[string]string{}
	for name, i := range composeServiceInfos(compose) {
		out[name] = i.image
	}
	return out
}

// ImageDigest is an image reference's pinned digest (the part after
// "@", e.g. "sha256:…"; "" when it isn't pinned by digest).
func ImageDigest(ref string) string {
	if _, d, ok := strings.Cut(ref, "@"); ok {
		return d
	}
	return ""
}

// ServiceNet is one service's network attachment as compose.yml declares it.
type ServiceNet struct {
	Networks    []string
	NetworkMode bool
}

// HasAIMCP reports whether t's template declares ai.mcp companions (not
// ai.unsupported).
func (t *Template) HasAIMCP() bool {
	a := t.Manifest.AI
	return a != nil && a.Unsupported == "" && len(a.MCP) > 0
}

// checkTrustNetwork: an identity_headers companion service joins exactly one
// network, its trust network — a project network other than default and
// portcullis-proxy, declared internal: true, whose members are exactly the
// companion and the services carrying its router (the app that trusts the
// identity headers). No other service joins it or shares a member's network
// namespace, so the app may trust the headers from that network's
// addresses (contract §3.2) without pinning an address or a subnet.
func checkTrustNetwork(w string, c *Companion, compose []byte, infos map[string]composeServiceInfo, routes *Routes) error {
	nets := infos[c.Service].networks
	if len(nets) != 1 || nets[0] == "default" || nets[0] == proxyNetwork {
		return fmt.Errorf("%s: identity_headers companion service %s must join exactly one network, its trust network (an internal: true project network shared only with the app that trusts the headers), not %v", w, c.Service, nets)
	}
	trust := nets[0]
	var doc struct {
		Networks map[string]interface{} `yaml:"networks"`
	}
	_ = yaml.Unmarshal(compose, &doc)
	// Exactly {internal: true}: no ipam, driver, driver_opts, enable_ipv6,
	// attachable, labels, name or external — an address plan or driver
	// option could make the subnet the app trusts cover other addresses.
	n, _ := doc.Networks[trust].(map[string]interface{})
	if in, ok := n["internal"].(bool); !ok || !in || len(n) != 1 {
		return fmt.Errorf("%s: the trust network %s must be declared at the top level as exactly {internal: true} (no ipam, driver, driver_opts, enable_ipv6, attachable, labels, name or external)", w, trust)
	}
	want := map[string]bool{c.Service: true}
	for svc, rs := range routes.Routers {
		if slices.Contains(rs, c.Router) {
			want[svc] = true
		}
	}
	if len(want) < 2 {
		return fmt.Errorf("%s: no compose service carries router %s (the app that trusts the identity headers)", w, c.Router)
	}
	for _, name := range slices.Sorted(maps.Keys(infos)) {
		in := slices.Contains(infos[name].networks, trust)
		if in && !want[name] {
			return fmt.Errorf("%s: service %s joins the trust network %s: only the companion %s and the service(s) of router %s may (any other member could send identity headers the app trusts)", w, name, trust, c.Service, c.Router)
		}
		if !in && want[name] {
			return fmt.Errorf("%s: service %s (router %s) must join the trust network %s", w, name, c.Router, trust)
		}
		if mode := infos[name].netModeOf; strings.HasPrefix(mode, "service:") && want[strings.TrimPrefix(mode, "service:")] {
			return fmt.Errorf("%s: service %s uses network_mode %s: it would share an address on the trust network %s", w, name, mode, trust)
		}
		if pid := infos[name].pidOf; strings.HasPrefix(pid, "service:") && want[strings.TrimPrefix(pid, "service:")] {
			return fmt.Errorf("%s: service %s uses pid %s: it would share the process namespace of a trust network member (%s)", w, name, pid, trust)
		}
	}
	return nil
}

// checkCallerSecretScope: an identity_headers caller secret reaches only the
// companion's service — no other service may interpolate it (${VAR…} or
// $VAR, anywhere in its definition, nested defaults included).
func checkCallerSecretScope(w string, c *Companion, compose []byte) error {
	env := ""
	if c.Identity.CallerSecret != nil {
		env = c.Identity.CallerSecret.Env
	}
	if env == "" {
		return nil
	}
	var doc struct {
		Services map[string]interface{} `yaml:"services"`
	}
	if yaml.Unmarshal(compose, &doc) != nil {
		return nil
	}
	for _, name := range slices.Sorted(maps.Keys(doc.Services)) {
		if name == c.Service {
			continue
		}
		var found bool
		_ = walkStrings(doc.Services[name], func(s string) error {
			for _, r := range rawVarRefs(s) {
				if r.name == env {
					found = true
				}
			}
			return nil
		})
		if found {
			return fmt.Errorf("%s: service %s reads the caller secret %s: only the companion service %s may", w, name, env, c.Service)
		}
	}
	return nil
}
