// Package freshauth verifies a proof that a person signed in with a
// passkey or a YubiKey certificate just now (contract §8 "Fresh-auth
// client", §5.1, §8.1 "Session methods"): the
// browser runs an OIDC authorization-code flow with PKCE on the Hub-owned
// public Keycloak client ClientID in a popup and posts the code, its PKCE
// verifier and the nonce; the Hub exchanges the code itself (Keycloak's
// codes are single-use, so a replay fails) and checks the ID token.
//
// Shared by the file-sharing and certificates projects. Libraries:
// golang.org/x/oauth2 (the code exchange with oauth2.VerifierOption) and
// github.com/coreos/go-oidc/v3 (signature over the realm's JWKS, issuer,
// audience, expiry, algorithms); the remaining claim checks are here.
//
// Nothing a proof carries — code, verifier, nonce, tokens — ever reaches a
// log line, an error text or an Error's Reason: every refusal is an *Error
// whose Error() is the fixed Message and whose Reason is one of this
// package's fixed strings.
package freshauth

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// ClientID is the Hub-owned Keycloak client (also its owner tag).
const ClientID = "portcullis-fresh-auth"

// MaxAge is how old the sign-in (auth_time) may be.
const MaxAge = 5 * time.Minute

// clockSkew is how far in the future iat / auth_time may be.
const clockSkew = 60 * time.Second

// Message is the one text every refusal answers (403).
const Message = "a fresh passkey sign-in is required"

// FreshMethods are the only sign-in methods (contract §8.1) whose
// pc_fresh proves a fresh sign-in: any passkey kind or a YubiKey
// certificate — each only while Config.Accepted lists it (switched on).
// Never a password, a browser certificate or a setup link (none of them
// sets pc_fresh; any of them named there is refused whatever Accepted
// returns).
//
// The claim pc_fresh is set by the Keycloak extension's portcullis-fresh
// mapper on the fresh-auth client, from this authentication's notes only:
// the authenticator that actually ran in this sign-in. amr is never read —
// Keycloak accumulates it over the SSO session (10 h), so a fresh password
// sign-in could still carry an older hwk.
var FreshMethods = []string{"passkey_synced", "passkey_device", "security_key", "yubikey_cert"}

// ClaimFresh is the ID token claim naming this authentication's method.
const ClaimFresh = "pc_fresh"

// supportedAlgs are the only ID token signature algorithms accepted.
var supportedAlgs = []string{oidc.RS256, oidc.ES256}

// Bounds on what a browser may post (contract §5.1 caps the body at 8 KiB).
const (
	maxCode  = 4096
	maxNonce = 512
)

// codeVerifierRe is RFC 7636 §4.1: 43–128 unreserved characters.
var codeVerifierRe = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)

// Config wires a Verifier.
type Config struct {
	Issuer       string // <public>/realms/portcullis
	TokenURL     string // http://keycloak:8080/realms/portcullis/protocol/openid-connect/token
	JWKSURL      string // http://keycloak:8080/realms/portcullis/protocol/openid-connect/certs
	AuthorizeURL string // <public>/realms/portcullis/protocol/openid-connect/auth
	RedirectURI  string // https://people.<domain>/
	HTTP         *http.Client
	Now          func() time.Time
	// Accepted returns the fresh methods (FreshMethods) switched on right
	// now; read on every proof. nil, or a method missing from its answer,
	// refuses (fail closed).
	Accepted func() []string
}

// Proof is what the browser posts.
type Proof struct{ Code, CodeVerifier, Nonce string }

// Result is an accepted proof.
type Result struct {
	User     string // lowercase
	AuthTime time.Time
	// Method is pc_fresh: one of FreshMethods, switched on at Verify.
	Method string
}

// ReasonUnreachable: the token endpoint or the realm's keys (JWKS)
// couldn't be reached (a Hub-side outage, not the caller's refusal: the
// Hub answers 503).
const ReasonUnreachable = "code exchange failed: Keycloak unreachable"

// Error is a refused proof: always answered 403 with Message; Reason
// (a fixed string, never a proof value) goes only to the audit.
type Error struct{ Reason string }

func (e *Error) Error() string { return Message }

// Status is the HTTP status of every refusal.
func (e *Error) Status() int { return http.StatusForbidden }

func refuse(reason string) error { return &Error{Reason: reason} }

// Verifier checks proofs. Safe for concurrent use.
type Verifier struct {
	cfg      Config
	oauth    *oauth2.Config
	verifier *oidc.IDTokenVerifier
}

// New returns a Verifier. The keys are fetched from cfg.JWKSURL on first
// use and cached (re-fetched for an unknown key id). A Config without an
// issuer, token URL or JWKS URL gives a Verifier that refuses every proof.
func New(cfg Config) *Verifier {
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	v := &Verifier{cfg: cfg}
	if cfg.Issuer == "" || cfg.TokenURL == "" || cfg.JWKSURL == "" || cfg.RedirectURI == "" {
		return v
	}
	v.oauth = &oauth2.Config{
		ClientID:    ClientID,
		Endpoint:    oauth2.Endpoint{AuthURL: cfg.AuthorizeURL, TokenURL: cfg.TokenURL, AuthStyle: oauth2.AuthStyleInParams},
		RedirectURL: cfg.RedirectURI,
	}
	keys := oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), cfg.HTTP), cfg.JWKSURL)
	v.verifier = oidc.NewVerifier(cfg.Issuer, keys, &oidc.Config{
		ClientID:             ClientID,
		SupportedSigningAlgs: supportedAlgs,
		Now:                  cfg.Now,
	})
	return v
}

// AuthorizeInfo is what the page needs to start the popup flow.
type AuthorizeInfo struct {
	AuthorizeURL string `json:"authorize_url"`
	ClientID     string `json:"client_id"`
	RedirectURI  string `json:"redirect_uri"`
}

// Info returns the authorize endpoint, client id and redirect URI.
func (v *Verifier) Info() AuthorizeInfo {
	return AuthorizeInfo{AuthorizeURL: v.cfg.AuthorizeURL, ClientID: ClientID, RedirectURI: v.cfg.RedirectURI}
}

// claims are the ID token claims checked here (go-oidc checks iss, aud,
// exp and the signature).
type claims struct {
	Subject  string          `json:"sub"`
	AZP      *string         `json:"azp"`
	AuthTime *int64          `json:"auth_time"`
	IssuedAt *int64          `json:"iat"`
	Fresh    json.RawMessage `json:"pc_fresh"`
	ACR      json.RawMessage `json:"acr"`
	Username *string         `json:"preferred_username"`
}

// Verify exchanges p.Code (with the PKCE verifier) and checks the ID token
// for user (compared lowercased). Any failure is an *Error.
func (v *Verifier) Verify(ctx context.Context, p Proof, user string) (*Result, error) {
	if v.oauth == nil || v.verifier == nil {
		return nil, refuse("fresh auth is not configured")
	}
	user = strings.ToLower(user)
	switch {
	case user == "":
		return nil, refuse("no caller")
	case p.Code == "" || len(p.Code) > maxCode:
		return nil, refuse("missing or oversized code")
	case !codeVerifierRe.MatchString(p.CodeVerifier):
		return nil, refuse("malformed code verifier")
	case p.Nonce == "" || len(p.Nonce) > maxNonce:
		return nil, refuse("missing or oversized nonce")
	}
	now := v.cfg.Now()

	tok, err := v.oauth.Exchange(oidc.ClientContext(ctx, v.cfg.HTTP), p.Code, oauth2.VerifierOption(p.CodeVerifier))
	if err != nil {
		var re *oauth2.RetrieveError
		if errors.As(err, &re) {
			if re.ErrorCode == "invalid_grant" {
				return nil, refuse("code exchange refused: invalid_grant (expired, replayed or wrong verifier)")
			}
			return nil, refuse("code exchange refused by Keycloak")
		}
		return nil, refuse(ReasonUnreachable)
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return nil, refuse("no id token in the token response")
	}
	idt, err := v.verifier.Verify(ctx, raw)
	if err != nil {
		return nil, refuse(oidcReason(err))
	}
	var c claims
	if err := idt.Claims(&c); err != nil {
		return nil, refuse("malformed id token claims")
	}

	// aud contains the client (go-oidc); azp, when present, is the client;
	// several audiences need azp.
	if c.AZP != nil && *c.AZP != ClientID {
		return nil, refuse("azp is another client")
	}
	if c.AZP == nil && len(idt.Audience) != 1 {
		return nil, refuse("several audiences without azp")
	}
	if c.IssuedAt == nil {
		return nil, refuse("missing iat")
	}
	if time.Unix(*c.IssuedAt, 0).After(now.Add(clockSkew)) {
		return nil, refuse("iat in the future")
	}
	if idt.Nonce == "" {
		return nil, refuse("missing nonce in the id token")
	}
	if subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(p.Nonce)) != 1 {
		return nil, refuse("nonce mismatch")
	}
	if c.AuthTime == nil {
		return nil, refuse("missing auth_time")
	}
	authTime := time.Unix(*c.AuthTime, 0)
	if authTime.Before(now.Add(-MaxAge)) {
		return nil, refuse("sign-in older than 5 minutes")
	}
	if authTime.After(now.Add(clockSkew)) {
		return nil, refuse("auth_time in the future")
	}
	method, reason := v.freshMethod(c.Fresh)
	if reason != "" {
		return nil, refuse(reason)
	}
	if slices.ContainsFunc(acrValues(c.ACR), isFile) {
		return nil, refuse("acr contains file")
	}
	if idt.Subject == "" {
		return nil, refuse("missing sub")
	}
	if c.Username == nil || *c.Username == "" {
		return nil, refuse("missing preferred_username")
	}
	if strings.ToLower(*c.Username) != user {
		return nil, refuse("signed in as another person")
	}
	return &Result{User: user, AuthTime: authTime, Method: method}, nil
}

// freshMethod checks pc_fresh (raw): a JSON string, one of FreshMethods
// (exact), and among Accepted's answer. Anything else is a refusal reason.
func (v *Verifier) freshMethod(raw json.RawMessage) (string, string) {
	var m string
	if len(raw) == 0 || json.Unmarshal(raw, &m) != nil || m == "" {
		return "", "missing " + ClaimFresh
	}
	if !slices.Contains(FreshMethods, m) {
		return "", ClaimFresh + " is not a passkey or a YubiKey certificate"
	}
	if v.cfg.Accepted == nil || !slices.Contains(v.cfg.Accepted(), m) {
		return "", ClaimFresh + " names a method that is switched off"
	}
	return m, ""
}

func isFile(s string) bool { return strings.EqualFold(s, "file") }

// stringList decodes a JSON array of strings (anything else: false).
func stringList(raw json.RawMessage) ([]string, bool) {
	if len(raw) == 0 {
		return nil, false
	}
	var out []string
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, false
	}
	return out, true
}

// acrValues reads acr as a string (space-separated values) or a list
// (absent or null: none). An unreadable acr reads as "file", so that it is
// refused (fail closed).
func acrValues(raw json.RawMessage) []string {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return strings.Fields(s)
	}
	if l, ok := stringList(raw); ok {
		return l
	}
	return []string{"file"}
}

// oidcReason maps a go-oidc error to a fixed reason (its texts may quote
// claim values).
func oidcReason(err error) string {
	var te *oidc.TokenExpiredError
	if errors.As(err, &te) {
		return "id token expired"
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "different provider"):
		return "id token from another issuer"
	case strings.Contains(msg, "expected audience"):
		return "id token audience is not the fresh-auth client"
	case strings.Contains(msg, "signing algorithm") || strings.Contains(msg, "unsupported") || strings.Contains(msg, "malformed jwt"):
		return "id token malformed or signed with an unsupported algorithm"
	case strings.Contains(msg, "fetching keys"):
		// N3: the realm's JWKS can't be fetched — a Hub-side outage
		// (503, not the caller's refusal); a bad signature or an unknown
		// kid never says this.
		return ReasonUnreachable
	case strings.Contains(msg, "signature") || strings.Contains(msg, "keys"):
		return "id token signature not verified by the realm's keys"
	case strings.Contains(msg, "nbf"):
		return "id token not yet valid"
	}
	return "id token not verified"
}
