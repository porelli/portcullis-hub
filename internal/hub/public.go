package hub

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/templates"
)

// Public path exceptions (auth.public_access): the Hub, not the template,
// generates the public router, because only the Hub knows whether the
// exception is on, which shares are listed and which TLS tier the host
// gets. A template can't ship a router that skips forward-auth.

// coreIdentityHeaders are always deleted from requests on the public
// router: it has no forward-auth, so nothing else removes client-supplied
// copies. They are core's forward-auth authResponseHeaders (minus
// Authorization: public WebDAV and share APIs use it) and Remote-*. The
// template's auth.identity_headers are added (required for header-auth).
var coreIdentityHeaders = []string{
	"Remote-Email", "Remote-Groups", "Remote-Name", "Remote-User",
	"X-Auth-Request-Access-Token", "X-Auth-Request-Email", "X-Auth-Request-Groups",
	"X-Auth-Request-Preferred-Username", "X-Auth-Request-User",
	"X-Forwarded-Access-Token", "X-Forwarded-Email", "X-Forwarded-Groups",
	"X-Forwarded-Preferred-Username", "X-Forwarded-User",
}

// publicStripHeaders returns the headers deleted on an app's public router,
// each also in its underscore form (X_Forwarded_User): some servers read
// "_" as "-". Core's entrypoints also delete such aliases
// (aliasHeadersStrategy=delete); this does not rely on it.
func publicStripHeaders(m *templates.Manifest) []string {
	set := map[string]bool{}
	for _, h := range append(append([]string(nil), coreIdentityHeaders...), m.Auth.IdentityHeaders...) {
		set[http.CanonicalHeaderKey(h)] = true
		set[strings.ReplaceAll(http.CanonicalHeaderKey(h), "-", "_")] = true
	}
	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// PublicRouterName is the Traefik router the Hub adds for an app's public
// paths; PublicStripMiddleware the header-stripping middleware it uses.
func PublicRouterName(id string) string { return templates.ReservedPrefix + id }

// PublicStripMiddleware names the app's identity-header strip middleware.
func PublicStripMiddleware(id string) string { return templates.ReservedPrefix + "strip-" + id }

// publicState is an app's effective public exception.
type publicState struct {
	Declared bool
	Enabled  bool // the toggle (admin choice, else template default)
	Explicit bool // the admin chose
	Mode     string
	Tokens   []string // listed tokens valid for the template
	// InvalidTokens are stored tokens the template no longer accepts.
	InvalidTokens []string
	// Blocked explains why a stored choice opens nothing.
	Blocked string
	// Routed are the literal prefixes of the public router, Published the
	// same with {token} kept. Empty: no public router.
	Routed, Published []string
}

// Active reports whether a public router is generated.
func (p publicState) Active() bool { return len(p.Routed) > 0 }

// publicLocked computes an app's public exception from its manifest, the
// plan and state. Caller must hold mu.
func (h *Hub) publicLocked(t *templates.Template, plan *templates.PublicPlan) publicState {
	pa := t.Manifest.Auth.PublicAccess
	if pa == nil {
		return publicState{}
	}
	ps := publicState{Declared: true, Enabled: pa.EnabledByDefault, Mode: pa.Mode()}
	if on, ok := h.st.PublicAccess[t.ID]; ok {
		ps.Enabled, ps.Explicit = on, true
	}
	// Fail closed: a stored choice the template no longer supports opens
	// nothing (never a wider mode) until an admin confirms a mode.
	if m, ok := h.st.PublicMode[t.ID]; ok {
		ps.Mode = m
		switch {
		case m == templates.ModeListed && !pa.HasTokenPaths():
			ps.Blocked = "public exception disabled: the template no longer supports per-share listing; confirm a mode"
		case m != templates.ModeListed && m != templates.ModeAll:
			ps.Blocked = fmt.Sprintf("public exception disabled: stored mode %q is unknown; confirm a mode", m)
		}
	}
	// Listed tokens the template's token_pattern no longer accepts are not
	// routed (narrower is safe) and are shown in the settings.
	for _, tok := range h.st.PublicTokens[t.ID] {
		if got, err := templates.ExtractToken(pa, tok); err == nil && got == tok {
			ps.Tokens = append(ps.Tokens, tok)
		} else {
			ps.InvalidTokens = append(ps.InvalidTokens, tok)
		}
	}
	if ps.Enabled && plan != nil && ps.Blocked == "" {
		tokens := ps.Tokens
		if ps.Mode != templates.ModeListed {
			tokens = nil
		}
		ps.Routed, ps.Published = plan.Effective(ps.Mode, tokens)
	}
	return ps
}

// publicLabels renders the public router and its strip middleware as
// override label lines (4-space indented under the service's labels).
func publicLabels(id string, m *templates.Manifest, plan *templates.PublicPlan, routed []string, tier string) ([]string, error) {
	rule := plan.Rule(routed)
	// Self-check: the router must stay inside the hosts the Hub knows.
	if _, err := templates.ParseRule(rule); err != nil {
		return nil, fmt.Errorf("public router rule: %w", err)
	}
	q := func(s string) string {
		var b strings.Builder
		enc := json.NewEncoder(&b)
		enc.SetEscapeHTML(false)
		enc.Encode(s) // JSON string == YAML double-quoted scalar
		return strings.TrimSpace(b.String())
	}
	r, mw := "traefik.http.routers."+PublicRouterName(id), PublicStripMiddleware(id)
	lines := []string{
		r + ".rule: " + q(rule),
		r + ".entrypoints: websecure",
		r + `.tls: "true"`,
		r + ".tls.options: " + tier,
		r + fmt.Sprintf(`.priority: "%d"`, plan.Priority),
		r + ".middlewares: " + mw + "@docker,rate-limit@file,security-headers@file",
	}
	if plan.TraefikService != "" {
		lines = append(lines, r+".service: "+q(plan.TraefikService))
	}
	for _, hdr := range publicStripHeaders(m) {
		lines = append(lines, "traefik.http.middlewares."+mw+".headers.customrequestheaders."+hdr+`: ""`)
	}
	return lines, nil
}

// PublicAccessView is the settings payload for auth.public_access.
type PublicAccessView struct {
	Description      string                 `json:"description"`
	Paths            []templates.PublicPath `json:"paths"`
	EnabledByDefault bool                   `json:"enabled_by_default"`
	DefaultMode      string                 `json:"default_mode"`
	TokenPattern     string                 `json:"token_pattern,omitempty"`
	ListedPossible   bool                   `json:"listed_possible"`
	MaxTokens        int                    `json:"max_tokens"`
	Enabled          bool                   `json:"enabled"`
	Explicit         bool                   `json:"explicit"`
	Mode             string                 `json:"mode"`
	Tokens           []string               `json:"tokens"`
	Active           bool                   `json:"active"`
	Published        []string               `json:"published"`
	Method           string                 `json:"method"`
	Subdomains       []string               `json:"subdomains"`
	// PolicyTier is the TLS tier the policy alone gives; TierWhenActive
	// what all of the app's routers get while the public router exists.
	PolicyTier     string `json:"policy_tier"`
	TierWhenActive string `json:"tier_when_active"`
	// UngatedRouters have no group-gate: with the tier downgraded, nothing
	// checks a client cert on their requests (native-OIDC: only at login).
	UngatedRouters []string `json:"ungated_routers"`
	InvalidTokens  []string `json:"invalid_tokens,omitempty"`
	Blocked        string   `json:"blocked,omitempty"`
	Error          string   `json:"error,omitempty"`
}

// publicViewLocked builds the settings view. Caller must hold mu.
func (h *Hub) publicViewLocked(t *templates.Template, eff policy.AuthPolicy) *PublicAccessView {
	pa := t.Manifest.Auth.PublicAccess
	if pa == nil {
		return nil
	}
	ps := h.publicLocked(t, t.Public)
	v := &PublicAccessView{
		Description: pa.Description, Paths: pa.Paths, EnabledByDefault: pa.EnabledByDefault,
		DefaultMode: pa.Mode(), TokenPattern: pa.TokenPattern, ListedPossible: pa.HasTokenPaths(),
		MaxTokens: templates.MaxPublicTokens, Enabled: ps.Enabled, Explicit: ps.Explicit, Mode: ps.Mode,
		Tokens: ps.Tokens, Active: ps.Active(), Published: ps.Published, Method: t.Manifest.Auth.Method,
		PolicyTier: policy.Tier(eff), TierWhenActive: policy.HostTier(eff, true),
		UngatedRouters: []string{}, InvalidTokens: ps.InvalidTokens, Blocked: ps.Blocked,
	}
	if v.Tokens == nil {
		v.Tokens = []string{}
	}
	if t.Public != nil {
		v.Subdomains = t.Public.Subdomains
	}
	if routes, err := templates.ParseRoutes(t.ReadCompose()); err != nil {
		v.Error = err.Error()
	} else {
		for name, ri := range routes.Info {
			if !ri.Gated() {
				v.UngatedRouters = append(v.UngatedRouters, name)
			}
		}
		sort.Strings(v.UngatedRouters)
	}
	return v
}

// applyPublicUpdateLocked validates and applies the public-access part of
// a settings update to state. Returns whether anything changed. Caller
// must hold mu (write).
func (h *Hub) applyPublicUpdateLocked(t *templates.Template, u SettingsUpdate) (bool, error) {
	pa := t.Manifest.Auth.PublicAccess
	if u.PublicAccess == nil && !u.PublicAccessDefault && u.PublicMode == nil && u.PublicTokens == nil {
		return false, nil
	}
	if pa == nil {
		return false, statusErr(400, "%s declares no public exceptions", t.ID)
	}
	var tokens []string
	if u.PublicTokens != nil {
		if len(*u.PublicTokens) > 0 && !pa.HasTokenPaths() {
			return false, statusErr(400, "%s has no per-share paths; it can only open all shares", t.ID)
		}
		seen := map[string]bool{}
		for _, in := range *u.PublicTokens {
			if strings.TrimSpace(in) == "" {
				continue
			}
			tok, err := templates.ExtractToken(pa, in)
			if err != nil {
				return false, statusErr(400, "%v", err)
			}
			if !seen[tok] {
				seen[tok] = true
				tokens = append(tokens, tok)
			}
		}
		if len(tokens) > templates.MaxPublicTokens {
			return false, statusErr(400, "at most %d listed shares per app (got %d)", templates.MaxPublicTokens, len(tokens))
		}
	}
	if u.PublicMode != nil {
		switch m := *u.PublicMode; m {
		case "", templates.ModeAll:
		case templates.ModeListed:
			if !pa.HasTokenPaths() {
				return false, statusErr(400, "%s has no per-share paths; mode listed is not available", t.ID)
			}
		default:
			return false, statusErr(400, "public mode must be all or listed")
		}
	}

	before := h.publicLocked(t, t.Public)
	prevOn, hadOn := h.st.PublicAccess[t.ID]
	prevMode, hadMode := h.st.PublicMode[t.ID]
	prevTokens, hadTokens := h.st.PublicTokens[t.ID]
	restore := func() {
		if hadOn {
			h.st.PublicAccess[t.ID] = prevOn
		} else {
			delete(h.st.PublicAccess, t.ID)
		}
		if hadMode {
			h.st.PublicMode[t.ID] = prevMode
		} else {
			delete(h.st.PublicMode, t.ID)
		}
		if hadTokens {
			h.st.PublicTokens[t.ID] = prevTokens
		} else {
			delete(h.st.PublicTokens, t.ID)
		}
	}
	switch {
	case u.PublicAccessDefault:
		delete(h.st.PublicAccess, t.ID)
	case u.PublicAccess != nil:
		h.st.PublicAccess[t.ID] = *u.PublicAccess
	}
	if u.PublicMode != nil {
		if *u.PublicMode == "" {
			delete(h.st.PublicMode, t.ID)
		} else {
			h.st.PublicMode[t.ID] = *u.PublicMode
		}
	}
	if u.PublicTokens != nil {
		if len(tokens) == 0 {
			delete(h.st.PublicTokens, t.ID)
		} else {
			h.st.PublicTokens[t.ID] = tokens
		}
	}
	// Any public-access choice pins the mode it was made under, so a later
	// template default_mode change can't widen it.
	if _, ok := h.st.PublicMode[t.ID]; !ok && (u.PublicAccess != nil || u.PublicTokens != nil) {
		h.st.PublicMode[t.ID] = before.Mode
	}
	after := h.publicLocked(t, t.Public)
	if after.Active() && t.Public == nil {
		restore()
		return false, statusErr(400, "public exceptions of %s can't be routed", t.ID)
	}
	return !equalStrings(before.Routed, after.Routed) || before.Enabled != after.Enabled || before.Blocked != after.Blocked ||
		before.Explicit != after.Explicit || before.Mode != after.Mode || !equalStrings(before.Tokens, after.Tokens), nil
}

func equalStrings(a, b []string) bool {
	return strings.Join(a, "\x00") == strings.Join(b, "\x00") && len(a) == len(b)
}
