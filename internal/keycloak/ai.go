package keycloak

import (
	"context"
	"errors"
	"fmt"
	"log"
	"maps"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Nerzal/gocloak/v14"
)

// AI clients and mcp:* scopes (contract §8 "AI clients", "mcp:* scopes",
// "Disconnecting").

// AIOwner is the owner tag (OwnerAttr) of the Hub's three AI clients.
const AIOwner = "portcullis-ai"

// AIClientPrefix starts the Hub's AI client ids. It is protected: no
// template registers such a client and RegisterClient never adopts one.
const AIClientPrefix = "portcullis-ai-"

// AIClientIDs are the Hub's AI clients (contract §8).
var AIClientIDs = struct{ Claude, ClaudeCode, Generic string }{"portcullis-ai-claude", "portcullis-ai-claude-code", "portcullis-ai-generic"}

// AIClientAttr is set to "true" on every client EnsureAIClient manages:
// the Hub's three and every ai_client entry (manifest
// keycloak_clients[].ai_client, tagged with its instance id). It is what
// marks an ai_client for the other syncs: attachAttributesScope skips it,
// RegisterClient / UpdateClientACR refuse it, SetOptionalScopes accepts
// it. The Hub sets it only through EnsureAIClient.
const AIClientAttr = "portcullis.hub.ai_client"

// AIUsernameMapper is the AI clients' one protocol mapper: the username
// as preferred_username in the access and the ID token (with only basic +
// acr Keycloak puts no username in a token).
const AIUsernameMapper = "portcullis-ai-username"

// MCPScopePrefix starts every Hub-owned MCP client scope.
const MCPScopePrefix = "mcp:"

// MCPAudienceMapper is the one protocol mapper of an mcp:* scope.
const MCPAudienceMapper = "portcullis-mcp-audience"

// MCPAllScope is "all my apps", the only MCP scope of an ai_client.
const MCPAllScope = "mcp:all"

// OfflineAccessScope is Keycloak's built-in offline_access scope, an
// optional scope of every AI client.
const OfflineAccessScope = "offline_access"

// AIDefaultScopes are exactly the default client scopes of an AI client:
// basic (sub, auth_time) and acr (acr, core's amr mapper). No profile,
// email, roles, groups, web-origins or attributes scope.
var AIDefaultScopes = []string{"basic", "acr"}

// AIDefaultACR is every AI client's default.acr.values.
const AIDefaultACR = "hwk"

// Redirect URIs of the Hub's AI clients (contract §8).
var (
	ClaudeRedirectURIs   = []string{"https://claude.ai/api/mcp/auth_callback"}
	LoopbackRedirectURIs = []string{"http://localhost:33418/callback", "http://127.0.0.1:33418/callback"}
)

// AIRedirectURIs returns the fixed redirect URIs of one of the Hub's AI
// clients (nil for any other id).
func AIRedirectURIs(clientID string) []string {
	switch clientID {
	case AIClientIDs.Claude:
		return slices.Clone(ClaudeRedirectURIs)
	case AIClientIDs.ClaudeCode, AIClientIDs.Generic:
		return slices.Clone(LoopbackRedirectURIs)
	}
	return nil
}

// Connection length bounds (Settings → AI, contract §8).
const (
	day            = 24 * time.Hour
	MinOfflineIdle = day
	MaxOfflineIdle = 30 * day
	MinOfflineMax  = day
	MaxOfflineMax  = 90 * day
)

const (
	attrOfflineIdle = "client.offline.session.idle.timeout"
	attrOfflineMax  = "client.offline.session.max.lifespan"
)

// ErrNotAIClient: the client is neither one of the Hub's AI clients
// (tagged AIOwner) nor an ai_client (AIClientAttr, owner-tagged).
var ErrNotAIClient = errors.New("not an AI client")

// AIClientSpec is what EnsureAIClient makes a client look like. For the
// Hub's three (AIClientIDs) Owner is AIOwner, Public is true, Secret is
// empty and RedirectURIs are exactly AIRedirectURIs(ClientID). Anything
// else is an ai_client: Owner its instance id, confidential (Secret set),
// its own https redirect URIs, OptionalScopes at most [mcp:all].
// OptionalScopes is the client's exact set of mcp:* optional scopes
// (offline_access is always kept besides them).
type AIClientSpec struct {
	ClientID, Name          string
	Public                  bool
	Secret                  string
	RedirectURIs            []string
	OptionalScopes          []string
	OfflineIdle, OfflineMax time.Duration
	Owner                   string
}

func isHubAIClient(id string) bool {
	return id == AIClientIDs.Claude || id == AIClientIDs.ClaudeCode || id == AIClientIDs.Generic
}

// hasAIPrefix: the protected prefix, case-insensitively.
func hasAIPrefix(id string) bool { return strings.HasPrefix(strings.ToLower(id), AIClientPrefix) }

// aiManaged reports whether a client representation is an AI client the
// Hub manages: one of its three tagged AIOwner, or an ai_client
// (AIClientAttr "true", owner-tagged with anything but AIOwner, no
// protected id).
func aiManaged(cl *gocloak.Client) bool {
	id, owner := str(cl.ClientID), cl.Attributes[OwnerAttr]
	if isHubAIClient(id) {
		return owner == AIOwner
	}
	return cl.Attributes[AIClientAttr] == "true" && owner != "" && owner != AIOwner && !protectedClient(id)
}

// skipsAttributesScope: clients the attributes scope never goes to (G9):
// protected ids, anything tagged AIOwner and every ai_client.
func skipsAttributesScope(cl *gocloak.Client) bool {
	return protectedClient(str(cl.ClientID)) || cl.Attributes[OwnerAttr] == AIOwner || cl.Attributes[AIClientAttr] == "true"
}

var mcpScopeRe = regexp.MustCompile(`^mcp:[a-z0-9]+(-[a-z0-9]+)*(\.[a-z0-9]+(-[a-z0-9]+)*)?$`)

// ValidMCPScope reports whether name is a well-formed mcp:* scope name.
func ValidMCPScope(name string) bool { return len(name) <= 200 && mcpScopeRe.MatchString(name) }

// checkMCPSet: every name an mcp:* scope, no duplicates; an ai_client
// (hub false) may hold only mcp:all.
func checkMCPSet(clientID string, hub bool, scopes []string) error {
	seen := map[string]bool{}
	for _, s := range scopes {
		if !ValidMCPScope(s) {
			return fmt.Errorf("client %s: %q is not an mcp:* scope", clientID, s)
		}
		if seen[s] {
			return fmt.Errorf("client %s: scope %s listed twice", clientID, s)
		}
		seen[s] = true
		if !hub && s != MCPAllScope {
			return fmt.Errorf("client %s: an ai_client gets only %s, not %s", clientID, MCPAllScope, s)
		}
	}
	return nil
}

func checkOneLine(what, s string, max int) error {
	if strings.TrimSpace(s) == "" || len(s) > max || strings.ContainsAny(s, "\r\n") || hasControl(s) {
		return fmt.Errorf("%s must be one non-empty line of at most %d bytes", what, max)
	}
	return nil
}

// hasControl reports whether s holds a control character.
func hasControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return true
		}
	}
	return false
}

// checkAppRedirect: an ai_client redirect URI is a plain https URL of a
// host (no wildcard, user info or fragment).
func checkAppRedirect(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" || strings.Contains(raw, "*") {
		return fmt.Errorf("redirect URI %q must be a plain https URL", raw)
	}
	return nil
}

func checkAISpec(s AIClientSpec) error {
	id := s.ClientID
	if isHubAIClient(id) {
		if s.Owner != AIOwner || !s.Public || s.Secret != "" {
			return fmt.Errorf("client %s: the Hub's AI clients are public and owned by %s", id, AIOwner)
		}
		if want := AIRedirectURIs(id); !sameSet(s.RedirectURIs, want) {
			return fmt.Errorf("client %s: redirect URIs must be exactly %v", id, want)
		}
	} else {
		switch {
		case id == "" || hasAIPrefix(id) || protectedClient(id):
			return fmt.Errorf("client %q can't be an ai_client", id)
		case s.Owner == "" || s.Owner == AIOwner:
			return fmt.Errorf("client %s: an ai_client is tagged with its instance id", id)
		case s.Public || s.Secret == "":
			return fmt.Errorf("client %s: an ai_client is confidential (secret required)", id)
		case len(s.RedirectURIs) == 0:
			return fmt.Errorf("client %s: no redirect URIs", id)
		}
		for _, r := range s.RedirectURIs {
			if err := checkAppRedirect(r); err != nil {
				return fmt.Errorf("client %s: %w", id, err)
			}
		}
	}
	if s.Name != "" {
		if err := checkOneLine("client "+id+": name", s.Name, 200); err != nil {
			return err
		}
	}
	if s.OfflineIdle < MinOfflineIdle || s.OfflineIdle > MaxOfflineIdle || s.OfflineIdle%time.Second != 0 {
		return fmt.Errorf("client %s: offline idle %v outside 1–30 days", id, s.OfflineIdle)
	}
	if s.OfflineMax < MinOfflineMax || s.OfflineMax > MaxOfflineMax || s.OfflineMax%time.Second != 0 {
		return fmt.Errorf("client %s: offline max %v outside 1–90 days", id, s.OfflineMax)
	}
	if s.OfflineIdle > s.OfflineMax {
		return fmt.Errorf("client %s: offline idle %v longer than the max %v", id, s.OfflineIdle, s.OfflineMax)
	}
	return checkMCPSet(id, isHubAIClient(id), s.OptionalScopes)
}

func sameSet(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}

func aiUsernameMapper() gocloak.ProtocolMapperRepresentation {
	return gocloak.ProtocolMapperRepresentation{
		Name:           gocloak.StringP(AIUsernameMapper),
		Protocol:       gocloak.StringP(oidcProtocol),
		ProtocolMapper: gocloak.StringP(oidcAttrMapper),
		Config: map[string]string{
			"user.attribute":            "username",
			"claim.name":                "preferred_username",
			"jsonType.label":            "String",
			"multivalued":               "false",
			"id.token.claim":            "true",
			"access.token.claim":        "true",
			"introspection.token.claim": "true",
			"userinfo.token.claim":      "false",
		},
	}
}

// withAISettings sets every asserted setting of s on rep.
func withAISettings(rep *gocloak.Client, s AIClientSpec) {
	name := s.Name
	if name == "" {
		name = s.ClientID
	}
	rep.Name = gocloak.StringP(name)
	rep.Enabled = gocloak.BoolP(true)
	rep.Protocol = gocloak.StringP(oidcProtocol)
	rep.PublicClient = gocloak.BoolP(s.Public)
	rep.BearerOnly = gocloak.BoolP(false)
	rep.ConsentRequired = gocloak.BoolP(true)
	rep.StandardFlowEnabled = gocloak.BoolP(true)
	rep.ImplicitFlowEnabled = gocloak.BoolP(false)
	rep.DirectAccessGrantsEnabled = gocloak.BoolP(false)
	rep.ServiceAccountsEnabled = gocloak.BoolP(false)
	rep.AuthorizationServicesEnabled = gocloak.BoolP(false)
	rep.FullScopeAllowed = gocloak.BoolP(false)
	if s.Public {
		rep.Secret = nil
	} else {
		rep.ClientAuthenticatorType = gocloak.StringP("client-secret")
		rep.Secret = gocloak.StringP(s.Secret)
	}
	rep.RedirectURIs = slices.Clone(s.RedirectURIs)
	rep.WebOrigins = []string{}
	rep.RootURL, rep.BaseURL, rep.AdminURL = nil, nil, nil
	if rep.Attributes == nil {
		rep.Attributes = map[string]string{}
	}
	maps.Copy(rep.Attributes, map[string]string{
		OwnerAttr:                    s.Owner,
		AIClientAttr:                 "true",
		"pkce.code.challenge.method": "S256",
		"default.acr.values":         AIDefaultACR,
		attrOfflineIdle:              strconv.FormatInt(int64(s.OfflineIdle/time.Second), 10),
		attrOfflineMax:               strconv.FormatInt(int64(s.OfflineMax/time.Second), 10),
		"oauth2.device.authorization.grant.enabled": "false",
		"oidc.ciba.grant.enabled":                   "false",
		"standard.token.exchange.enabled":           "false",
		"oauth2.jwt.authorization.grant.enabled":    "false",
	})
	if isHubAIClient(s.ClientID) {
		// The realm's browser flow only. An ai_client keeps its
		// instance's access flow (contract §8, G10).
		rep.AuthenticationFlowBindingOverrides = map[string]string{"browser": "", "direct_grant": ""}
	}
}

// clientPut is a client PUT body that always carries webOrigins
// (gocloak.Client tags it omitempty: an empty list would be dropped and
// Keycloak would keep the old origins).
type clientPut struct {
	gocloak.Client
	WebOrigins []string `json:"webOrigins"`
}

func (c *Client) putClientExact(ctx context.Context, tok string, cl *gocloak.Client) error {
	body := clientPut{Client: *cl, WebOrigins: cl.WebOrigins}
	if body.WebOrigins == nil {
		body.WebOrigins = []string{}
	}
	return c.rawSend(ctx, tok, http.MethodPut, "/clients/"+url.PathEscape(str(cl.ID)), "update client "+str(cl.ClientID), body)
}

// EnsureAIClient creates or re-asserts an AI client (contract §8):
// public (the Hub's three) or confidential (an ai_client), standard flow
// only, PKCE S256, consent required, default ACR hwk, fullScopeAllowed
// off, no direct grants / implicit / service accounts / device / CIBA /
// token exchange, the offline session idle and max in seconds, redirect
// URIs exactly s.RedirectURIs, no web origins, AIClientAttr set; default
// scopes exactly AIDefaultScopes, optional scopes exactly offline_access
// plus s.OptionalScopes; exactly one protocol mapper (AIUsernameMapper);
// the Hub's three get no flow overrides. An existing client of that id
// tagged with anyone but s.Owner (or untagged) is a *ConflictError, left
// alone. A realm without basic, acr, offline_access or one of the mcp:*
// scopes is an error (EnsureMCPScope them first). Scopes and mapper are
// reconciled before the client PUT; if one of those steps fails while the
// client still holds a disallowed scope or mapper, it is PUT disabled and
// the error returned (re-enabled by the next successful ensure). Any
// error: the caller keeps the client out of mcp-gate.json's clients.
func (c *Client) EnsureAIClient(ctx context.Context, s AIClientSpec) error {
	if err := checkAISpec(s); err != nil {
		return err
	}
	tok, err := c.token(ctx)
	if err != nil {
		return err
	}
	existing, err := c.findClient(ctx, tok, s.ClientID)
	if errors.Is(err, ErrClientNotFound) {
		rep := gocloak.Client{ClientID: gocloak.StringP(s.ClientID), DefaultClientScopes: slices.Clone(AIDefaultScopes),
			OptionalClientScopes: []string{OfflineAccessScope},
			ProtocolMappers:      []gocloak.ProtocolMapperRepresentation{aiUsernameMapper()}}
		withAISettings(&rep, s)
		rep.AuthenticationFlowBindingOverrides = nil
		_, err = c.api().CreateClient(ctx, tok, Realm, rep)
		if err != nil && statusCode(err) != http.StatusConflict {
			return opErr("create client "+s.ClientID, err)
		}
		if err == nil {
			log.Printf("Registered Keycloak AI client %s", s.ClientID)
		}
		existing, err = c.findClient(ctx, tok, s.ClientID)
	}
	if err != nil {
		return err
	}
	if owner := existing.Attributes[OwnerAttr]; owner != s.Owner {
		return &ConflictError{ClientID: s.ClientID, TemplateID: s.Owner, Owner: owner}
	}
	// Scopes and mapper first, then the PUT that keeps it enabled: a
	// client with a scope or mapper it must not have is never (re-)enabled.
	def, opt := AIDefaultScopes, append([]string{OfflineAccessScope}, s.OptionalScopes...)
	if err := c.reconcileAIScopesAndMapper(ctx, tok, existing, def, opt); err != nil {
		return c.disableIfDisallowed(ctx, tok, existing, s, def, opt, err)
	}
	withAISettings(existing, s)
	existing.ProtocolMappers = nil // the sub-resource above does those
	return c.putClientExact(ctx, tok, existing)
}

func (c *Client) reconcileAIScopesAndMapper(ctx context.Context, tok string, cl *gocloak.Client, def, opt []string) error {
	ids, err := c.scopeIDs(ctx, tok)
	if err != nil {
		return err
	}
	if err := c.exactScopes(ctx, tok, cl, ids, def, opt); err != nil {
		return err
	}
	return c.ensureOnlyClientMapper(ctx, tok, cl, aiUsernameMapper())
}

// disableIfDisallowed: a failed scope or mapper step (cause) leaves the
// client disabled when, read back, it still holds a scope outside
// def/opt or its mappers aren't exactly the username mapper
// (onlyMapper), or when it can't be read back — then existing (the
// representation EnsureAIClient holds) is PUT disabled by its id. Fail
// closed until the next successful ensure re-enables it. cause is
// returned either way, joined with any error on the way.
func (c *Client) disableIfDisallowed(ctx context.Context, tok string, existing *gocloak.Client, s AIClientSpec, def, opt []string, cause error) error {
	errs := []error{cause}
	cl, err := c.findClient(ctx, tok, s.ClientID)
	bad := false
	if err != nil {
		errs = append(errs, err)
		cl, bad = existing, true
	} else {
		for _, n := range cl.DefaultClientScopes {
			bad = bad || !slices.Contains(def, n)
		}
		for _, n := range cl.OptionalClientScopes {
			bad = bad || !slices.Contains(opt, n)
		}
		ms, err := c.clientMappers(ctx, tok, cl)
		if err != nil {
			errs = append(errs, err)
			bad = true
		} else if !onlyMapper(ms, aiUsernameMapper()) {
			bad = true
		}
	}
	if !bad {
		return cause
	}
	off := *cl
	off.Attributes = maps.Clone(cl.Attributes)
	withAISettings(&off, s)
	off.Enabled = gocloak.BoolP(false)
	off.ProtocolMappers = nil
	if err := c.putClientExact(ctx, tok, &off); err != nil {
		return errors.Join(append(errs, err)...)
	}
	log.Printf("Keycloak AI client %s disabled: it may keep a scope or mapper it must not have", s.ClientID)
	return fmt.Errorf("client %s disabled (a scope or mapper it must not have may be left): %w", s.ClientID, errors.Join(errs...))
}

// scopeIDs maps the realm's client scope names to ids.
func (c *Client) scopeIDs(ctx context.Context, tok string) (map[string]string, error) {
	scopes, err := c.api().GetClientScopes(ctx, tok, Realm)
	if err != nil {
		return nil, opErr("list client scopes", err)
	}
	ids := map[string]string{}
	for _, sc := range scopes {
		if sc != nil {
			ids[str(sc.Name)] = str(sc.ID)
		}
	}
	return ids, nil
}

// exactScopes makes cl's default scopes exactly def and its optional
// scopes exactly opt (detach first — never a wanted one —, then attach).
func (c *Client) exactScopes(ctx context.Context, tok string, cl *gocloak.Client, ids map[string]string, def, opt []string) error {
	g := c.api()
	cid, name := url.PathEscape(str(cl.ID)), str(cl.ClientID)
	for _, s := range append(slices.Clone(def), opt...) {
		if ids[s] == "" {
			return fmt.Errorf("client %s: the Keycloak realm has no %q client scope", name, s)
		}
	}
	for _, s := range cl.OptionalClientScopes {
		if ids[s] == "" || slices.Contains(opt, s) {
			continue
		}
		if err := g.RemoveOptionalScopeFromClient(ctx, tok, Realm, cid, url.PathEscape(ids[s])); err != nil {
			return opErr("detach optional scope "+s+" from client "+name, err)
		}
	}
	for _, s := range cl.DefaultClientScopes {
		if ids[s] == "" || slices.Contains(def, s) {
			continue
		}
		if err := g.RemoveDefaultScopeFromClient(ctx, tok, Realm, cid, url.PathEscape(ids[s])); err != nil {
			return opErr("detach default scope "+s+" from client "+name, err)
		}
	}
	for _, s := range def {
		if slices.Contains(cl.DefaultClientScopes, s) {
			continue
		}
		if err := g.AddDefaultScopeToClient(ctx, tok, Realm, cid, url.PathEscape(ids[s])); err != nil {
			return opErr("attach scope "+s+" to client "+name, err)
		}
	}
	for _, s := range opt {
		if slices.Contains(cl.OptionalClientScopes, s) {
			continue
		}
		if err := g.AddOptionalScopeToClient(ctx, tok, Realm, cid, url.PathEscape(ids[s])); err != nil {
			return opErr("attach optional scope "+s+" to client "+name, err)
		}
	}
	return nil
}

// onlyMapper: ms is exactly one mapper, named like want and sameMapper
// as want — the state ensureOnlyClientMapper produces and the one
// disableIfDisallowed accepts.
func onlyMapper(ms []gocloak.ProtocolMapperRepresentation, want gocloak.ProtocolMapperRepresentation) bool {
	return len(ms) == 1 && str(ms[0].Name) == str(want.Name) && sameMapper(ms[0], want)
}

// ensureOnlyClientMapper leaves exactly want on the client: any other
// client mapper (a hardcoded claim, a group mapper) is deleted.
func (c *Client) ensureOnlyClientMapper(ctx context.Context, tok string, cl *gocloak.Client, want gocloak.ProtocolMapperRepresentation) error {
	g := c.api()
	cid := url.PathEscape(str(cl.ID))
	have, err := c.clientMappers(ctx, tok, cl)
	if err != nil {
		return err
	}
	if onlyMapper(have, want) {
		return nil
	}
	kept := false
	for _, m := range have {
		if !kept && str(m.Name) == str(want.Name) && sameMapper(m, want) {
			kept = true
			continue
		}
		if err := g.DeleteClientProtocolMapper(ctx, tok, Realm, cid, url.PathEscape(str(m.ID))); err != nil && statusCode(err) != http.StatusNotFound {
			return opErr("delete protocol mapper "+str(m.Name)+" of client "+str(cl.ClientID), err)
		}
	}
	if kept {
		return nil
	}
	if _, err := g.CreateClientProtocolMapper(ctx, tok, Realm, cid, want); err != nil {
		return opErr("create protocol mapper "+str(want.Name), err)
	}
	return nil
}

// DeleteAIClient deletes an AI client: one of the Hub's three (owner
// must be AIOwner) or an ai_client tagged owner. A missing client is nil;
// one tagged otherwise, or (an ai_client) without AIClientAttr, is a
// *ConflictError and left alone.
func (c *Client) DeleteAIClient(ctx context.Context, clientID, owner string) error {
	hub := isHubAIClient(clientID)
	switch {
	case hub && owner != AIOwner, !hub && (owner == "" || owner == AIOwner || hasAIPrefix(clientID) || protectedClient(clientID)):
		return &ConflictError{ClientID: clientID, TemplateID: owner, Owner: "core"}
	}
	tok, err := c.token(ctx)
	if err != nil {
		return err
	}
	existing, err := c.findClient(ctx, tok, clientID)
	if errors.Is(err, ErrClientNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if got := existing.Attributes[OwnerAttr]; got != owner || !aiManaged(existing) {
		return &ConflictError{ClientID: clientID, TemplateID: owner, Owner: got}
	}
	if err := c.api().DeleteClient(ctx, tok, Realm, url.PathEscape(str(existing.ID))); err != nil && statusCode(err) != http.StatusNotFound {
		return opErr("delete client "+clientID, err)
	}
	log.Printf("Deleted Keycloak AI client %s", clientID)
	return nil
}

// aiClient finds clientID and checks it is an AI client (ErrNotAIClient
// otherwise; protected ids refused before any call).
func (c *Client) aiClient(ctx context.Context, tok, clientID string) (*gocloak.Client, error) {
	if protectedClients[clientID] {
		return nil, fmt.Errorf("client %s: %w", clientID, ErrNotAIClient)
	}
	cl, err := c.findClient(ctx, tok, clientID)
	if err != nil {
		return nil, err
	}
	if !aiManaged(cl) {
		return nil, fmt.Errorf("client %s: %w", clientID, ErrNotAIClient)
	}
	return cl, nil
}

// SetOptionalScopes makes the mcp:* optional scopes of an AI client
// exactly scopes (an ai_client: at most mcp:all). An mcp:* scope found
// among its default scopes is detached. Other scopes (offline_access,
// the defaults) are untouched. Any other client — core's, the fresh-auth
// client, app clients — is refused (ErrNotAIClient). A scope the realm
// doesn't have is an error.
func (c *Client) SetOptionalScopes(ctx context.Context, clientID string, scopes []string) error {
	if protectedClients[clientID] {
		return fmt.Errorf("client %s: %w", clientID, ErrNotAIClient)
	}
	if err := checkMCPSet(clientID, isHubAIClient(clientID), scopes); err != nil {
		return err
	}
	tok, err := c.token(ctx)
	if err != nil {
		return err
	}
	cl, err := c.aiClient(ctx, tok, clientID)
	if err != nil {
		return err
	}
	ids, err := c.scopeIDs(ctx, tok)
	if err != nil {
		return err
	}
	def, opt := []string{}, []string{}
	for _, s := range cl.DefaultClientScopes {
		if !strings.HasPrefix(s, MCPScopePrefix) {
			def = append(def, s)
		}
	}
	for _, s := range cl.OptionalClientScopes {
		if !strings.HasPrefix(s, MCPScopePrefix) {
			opt = append(opt, s)
		}
	}
	return c.exactScopes(ctx, tok, cl, ids, def, append(opt, scopes...))
}

// MCPScope is one MCP resource's client scope (contract §8): Audience is
// the resource URL, ConsentText the consent screen's line.
type MCPScope struct{ Name, Audience, ConsentText string }

func checkMCPScope(s MCPScope) error {
	if !ValidMCPScope(s.Name) {
		return fmt.Errorf("%q is not an mcp:* scope name", s.Name)
	}
	u, err := url.Parse(s.Audience)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.String() != s.Audience {
		return fmt.Errorf("scope %s: audience %q must be a plain https URL", s.Name, s.Audience)
	}
	return checkOneLine("scope "+s.Name+": consent text", s.ConsentText, 255)
}

func mcpAudienceMapper(audience string) gocloak.ProtocolMapperRepresentation {
	return gocloak.ProtocolMapperRepresentation{
		Name:           gocloak.StringP(MCPAudienceMapper),
		Protocol:       gocloak.StringP(oidcProtocol),
		ProtocolMapper: gocloak.StringP("oidc-audience-mapper"),
		Config: map[string]string{
			"included.custom.audience":  audience,
			"access.token.claim":        "true",
			"introspection.token.claim": "true",
			"id.token.claim":            "false",
			"lightweight.claim":         "false",
		},
	}
}

func mcpScopeAttrs(s MCPScope) *gocloak.ClientScopeAttributes {
	return &gocloak.ClientScopeAttributes{
		ConsentScreenText:      gocloak.StringP(s.ConsentText),
		DisplayOnConsentScreen: gocloak.StringP("true"),
		IncludeInTokenScope:    gocloak.StringP("true"),
	}
}

func (c *Client) findScope(ctx context.Context, tok, name string) (*gocloak.ClientScope, error) {
	scopes, err := c.api().GetClientScopes(ctx, tok, Realm)
	if err != nil {
		return nil, opErr("list client scopes", err)
	}
	for _, sc := range scopes {
		if sc != nil && str(sc.Name) == name && str(sc.ID) != "" {
			return sc, nil
		}
	}
	return nil, nil
}

// EnsureMCPScope creates or re-asserts the optional client scope s
// (contract §8): openid-connect, include.in.token.scope,
// display.on.consent.screen, consent.screen.text = s.ConsentText, and
// exactly one protocol mapper MCPAudienceMapper (included.custom.audience
// = s.Audience, access token only); other mappers on it are deleted. It is
// never one of the realm's default scopes (detached if found there). A
// scope of that name with another protocol is an error, left alone.
func (c *Client) EnsureMCPScope(ctx context.Context, s MCPScope) error {
	if err := checkMCPScope(s); err != nil {
		return err
	}
	tok, err := c.token(ctx)
	if err != nil {
		return err
	}
	g := c.api()
	sc, err := c.findScope(ctx, tok, s.Name)
	if err != nil {
		return err
	}
	if sc == nil {
		_, err := g.CreateClientScope(ctx, tok, Realm, gocloak.ClientScope{Name: gocloak.StringP(s.Name), Protocol: gocloak.StringP(oidcProtocol),
			Description: gocloak.StringP("Portcullis MCP resource " + s.Audience), ClientScopeAttributes: mcpScopeAttrs(s)})
		if err != nil && statusCode(err) != http.StatusConflict {
			return opErr("create client scope "+s.Name, err)
		}
		if sc, err = c.findScope(ctx, tok, s.Name); err != nil {
			return err
		}
		if sc == nil {
			return fmt.Errorf("client scope %s: not found after create", s.Name)
		}
	} else {
		if str(sc.Protocol) != oidcProtocol {
			return fmt.Errorf("client scope %s exists with protocol %q: left alone", s.Name, str(sc.Protocol))
		}
		a := sc.ClientScopeAttributes
		if a == nil || str(a.ConsentScreenText) != s.ConsentText || str(a.DisplayOnConsentScreen) != "true" || str(a.IncludeInTokenScope) != "true" ||
			str(sc.Description) != "Portcullis MCP resource "+s.Audience {
			up := gocloak.ClientScope{ID: sc.ID, Name: sc.Name, Protocol: sc.Protocol, Description: gocloak.StringP("Portcullis MCP resource " + s.Audience),
				ClientScopeAttributes: mcpScopeAttrs(s)}
			if err := g.UpdateClientScope(ctx, tok, Realm, up); err != nil {
				return opErr("update client scope "+s.Name, err)
			}
		}
	}
	sid := str(sc.ID)
	if err := c.ensureOnlyScopeMapper(ctx, tok, sid, s.Name, mcpAudienceMapper(s.Audience)); err != nil {
		return err
	}
	return c.dropRealmDefault(ctx, tok, sid, s.Name)
}

// Scope protocol mappers go through raw requests on gocloak's request
// builder: gocloak's typed scope-mapper config has no
// included.custom.audience.
func (c *Client) ensureOnlyScopeMapper(ctx context.Context, tok, sid, name string, want gocloak.ProtocolMapperRepresentation) error {
	path := "/client-scopes/" + url.PathEscape(sid) + "/protocol-mappers/models"
	var have []gocloak.ProtocolMapperRepresentation
	resp, err := c.api().GetRequestWithBearerAuth(ctx, tok).SetResult(&have).Get(c.BaseURL + "/admin/realms/" + Realm + path)
	if err != nil {
		return fmt.Errorf("list protocol mappers of scope %s: %w", name, err)
	}
	if resp.IsError() {
		return &HTTPError{Op: "list protocol mappers of scope " + name, Status: resp.StatusCode()}
	}
	kept := false
	for _, m := range have {
		if !kept && str(m.Name) == str(want.Name) && sameMapper(m, want) {
			kept = true
			continue
		}
		if err := c.rawSend(ctx, tok, http.MethodDelete, path+"/"+url.PathEscape(str(m.ID)), "delete protocol mapper "+str(m.Name)+" of scope "+name, nil); err != nil {
			var he *HTTPError
			if !errors.As(err, &he) || he.Status != http.StatusNotFound {
				return err
			}
		}
	}
	if kept {
		return nil
	}
	return c.rawSend(ctx, tok, http.MethodPost, path, "create protocol mapper "+str(want.Name)+" of scope "+name, want)
}

// dropRealmDefault detaches scope sid from the realm's default and
// optional default client scopes.
func (c *Client) dropRealmDefault(ctx context.Context, tok, sid, name string) error {
	g := c.api()
	def, err := g.GetDefaultDefaultClientScopes(ctx, tok, Realm)
	if err != nil {
		return opErr("list realm default client scopes", err)
	}
	opt, err := g.GetDefaultOptionalClientScopes(ctx, tok, Realm)
	if err != nil {
		return opErr("list realm optional client scopes", err)
	}
	for kind, list := range map[string][]*gocloak.ClientScope{"default-default-client-scopes": def, "default-optional-client-scopes": opt} {
		for _, sc := range list {
			if sc != nil && str(sc.ID) == sid {
				if err := c.rawSend(ctx, tok, http.MethodDelete, "/"+kind+"/"+url.PathEscape(sid), "detach "+name+" from the realm's "+kind, nil); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// DeleteMCPScope detaches the mcp:* scope name from every client and the
// realm's defaults, then deletes it (Keycloak drops it from consents with
// it). A missing scope is nil; a name outside mcp:* is refused.
func (c *Client) DeleteMCPScope(ctx context.Context, name string) error {
	if !ValidMCPScope(name) {
		return fmt.Errorf("%q is not an mcp:* scope name", name)
	}
	tok, err := c.token(ctx)
	if err != nil {
		return err
	}
	g := c.api()
	sc, err := c.findScope(ctx, tok, name)
	if err != nil || sc == nil {
		return err
	}
	sid := str(sc.ID)
	clients, err := g.GetClients(ctx, tok, Realm, gocloak.GetClientsParams{})
	if err != nil {
		return opErr("list clients", err)
	}
	for _, cl := range clients {
		if cl == nil || str(cl.ID) == "" {
			continue
		}
		cid := url.PathEscape(str(cl.ID))
		if slices.Contains(cl.OptionalClientScopes, name) {
			if err := g.RemoveOptionalScopeFromClient(ctx, tok, Realm, cid, url.PathEscape(sid)); err != nil && statusCode(err) != http.StatusNotFound {
				return opErr("detach optional scope "+name+" from client "+str(cl.ClientID), err)
			}
		}
		if slices.Contains(cl.DefaultClientScopes, name) {
			if err := g.RemoveDefaultScopeFromClient(ctx, tok, Realm, cid, url.PathEscape(sid)); err != nil && statusCode(err) != http.StatusNotFound {
				return opErr("detach default scope "+name+" from client "+str(cl.ClientID), err)
			}
		}
	}
	if err := c.dropRealmDefault(ctx, tok, sid, name); err != nil {
		return err
	}
	if err := g.DeleteClientScope(ctx, tok, Realm, url.PathEscape(sid)); err != nil && statusCode(err) != http.StatusNotFound {
		return opErr("delete client scope "+name, err)
	}
	log.Printf("Deleted Keycloak client scope %s", name)
	return nil
}

// AIConnection is one person's connection of an AI client: when they
// consented, when an offline session of it was last used, and when the
// longest-lived one expires (idle or max, the client's limits). Nil =
// unknown or none.
type AIConnection struct {
	Client                       string
	Consented, LastUsed, Expires *time.Time
}

type consentRep struct {
	ClientID        string `json:"clientId"`
	CreatedDate     int64  `json:"createdDate"`
	LastUpdatedDate int64  `json:"lastUpdatedDate"`
}

func msTime(ms int64) *time.Time {
	t := time.UnixMilli(ms).UTC()
	return &t
}

func secondsAttr(cl *gocloak.Client, key string) time.Duration {
	n, err := strconv.ParseInt(cl.Attributes[key], 10, 64)
	if err != nil || n <= 0 {
		return 0
	}
	return time.Duration(n) * time.Second
}

// AIConnections lists username's connections of clients (AI clients
// only; others and missing clients are skipped): a consent, offline
// sessions, or both. A user Keycloak doesn't know has none. Consents are
// read with a raw request (gocloak has no consent list).
func (c *Client) AIConnections(ctx context.Context, username string, clients []string) ([]AIConnection, error) {
	tok, err := c.token(ctx)
	if err != nil {
		return nil, err
	}
	u, err := c.findUser(ctx, tok, username)
	if err != nil || u == nil {
		return []AIConnection{}, err
	}
	uid := str(u.ID)
	var consents []consentRep
	resp, err := c.api().GetRequestWithBearerAuth(ctx, tok).SetResult(&consents).
		Get(c.BaseURL + "/admin/realms/" + Realm + "/users/" + url.PathEscape(uid) + "/consents")
	if err != nil {
		return nil, fmt.Errorf("list consents: %w", err)
	}
	if resp.IsError() {
		return nil, &HTTPError{Op: "list consents", Status: resp.StatusCode()}
	}
	byClient := map[string]consentRep{}
	for _, cr := range consents {
		// Keycloak also lists clients holding only offline tokens
		// (createdDate 0): those are counted from the sessions below.
		if cr.CreatedDate > 0 {
			byClient[cr.ClientID] = cr
		}
	}
	out := []AIConnection{}
	seen := map[string]bool{}
	for _, id := range clients {
		if seen[id] || protectedClients[id] {
			continue
		}
		seen[id] = true
		cl, err := c.findClient(ctx, tok, id)
		if errors.Is(err, ErrClientNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !aiManaged(cl) {
			continue
		}
		sessions, err := c.api().GetUserOfflineSessionsForClient(ctx, tok, Realm, url.PathEscape(uid), url.PathEscape(str(cl.ID)))
		if err != nil {
			return nil, opErr("list offline sessions of "+id, err)
		}
		conn := AIConnection{Client: id}
		if cr, ok := byClient[id]; ok {
			conn.Consented = msTime(cr.CreatedDate)
		}
		idle, max := secondsAttr(cl, attrOfflineIdle), secondsAttr(cl, attrOfflineMax)
		for _, s := range sessions {
			if s == nil || s.LastAccess == nil {
				continue
			}
			last := msTime(*s.LastAccess)
			if conn.LastUsed == nil || last.After(*conn.LastUsed) {
				conn.LastUsed = last
			}
			if idle > 0 && max > 0 && s.Start != nil {
				exp := last.Add(idle)
				if m := msTime(*s.Start).Add(max); m.Before(exp) {
					exp = m
				}
				if conn.Expires == nil || exp.After(*conn.Expires) {
					conn.Expires = &exp
				}
			}
		}
		if conn.Consented == nil && len(sessions) == 0 {
			continue
		}
		out = append(out, conn)
	}
	return out, nil
}

// RevokeAIConnection deletes username's consent to the AI client
// clientID; Keycloak's consent delete also revokes the client's offline
// tokens (and, with a consent, logs the client's online sessions out:
// see TestLiveAIObjects). The offline sessions are read back: one left is
// an error. Nothing to revoke (no consent, no offline session, an
// unknown user) is nil. Other clients' sessions stay.
func (c *Client) RevokeAIConnection(ctx context.Context, username, clientID string) error {
	tok, err := c.token(ctx)
	if err != nil {
		return err
	}
	cl, err := c.aiClient(ctx, tok, clientID)
	if err != nil {
		return err
	}
	u, err := c.findUser(ctx, tok, username)
	if err != nil || u == nil {
		return err
	}
	uid := url.PathEscape(str(u.ID))
	g := c.api()
	if err := g.RevokeUserConsents(ctx, tok, Realm, uid, url.PathEscape(clientID)); err != nil && statusCode(err) != http.StatusNotFound {
		return opErr("revoke consent to "+clientID, err)
	}
	left, err := g.GetUserOfflineSessionsForClient(ctx, tok, Realm, uid, url.PathEscape(str(cl.ID)))
	if err != nil {
		return opErr("list offline sessions of "+clientID, err)
	}
	if len(left) > 0 {
		return fmt.Errorf("revoke %s: %d offline session(s) left after the consent delete", clientID, len(left))
	}
	return nil
}
