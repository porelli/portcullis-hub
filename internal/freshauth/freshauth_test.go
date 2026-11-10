package freshauth_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/portcullis/hub/internal/freshauth"
)

const (
	issuer   = "https://auth.example.org/realms/portcullis"
	redirect = "https://people.example.org/"
	code     = "code-5f1d9a7e-2b44-4f0a-9d1c-6c3e1a2b3c4d"
	verifier = "verifier-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-._~"
	nonce    = "nonce-9b8a7c6d5e4f"
)

var now = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

// idp is an httptest token endpoint + JWKS. Each code is single-use
// (Keycloak's): a second exchange answers invalid_grant.
type idp struct {
	t       *testing.T
	srv     *httptest.Server
	rsaKey  *rsa.PrivateKey
	ecKey   *ecdsa.PrivateKey
	mu      sync.Mutex
	used    map[string]bool
	token   string // the id_token the next exchange returns
	posted  []map[string]string
	noToken bool
}

func newIDP(t *testing.T) *idp {
	t.Helper()
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := &idp{t: t, rsaKey: rk, ecKey: ek, used: map[string]bool{}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /realms/portcullis/protocol/openid-connect/token", p.serveToken)
	mux.HandleFunc("GET /realms/portcullis/protocol/openid-connect/certs", func(w http.ResponseWriter, r *http.Request) {
		set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &rk.PublicKey, KeyID: "rsa1", Algorithm: "RS256", Use: "sig"},
			{Key: &ek.PublicKey, KeyID: "ec1", Algorithm: "ES256", Use: "sig"},
		}}
		json.NewEncoder(w).Encode(set)
	})
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

func (p *idp) serveToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(400)
		return
	}
	got := map[string]string{}
	for k := range r.PostForm {
		got[k] = r.PostForm.Get(k)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.posted = append(p.posted, got)
	w.Header().Set("Content-Type", "application/json")
	c := r.PostForm.Get("code")
	if r.PostForm.Get("grant_type") != "authorization_code" || r.PostForm.Get("client_id") != freshauth.ClientID ||
		r.PostForm.Get("redirect_uri") != redirect || r.PostForm.Get("code_verifier") != verifier || p.used[c] || c == "" {
		w.WriteHeader(400)
		w.Write([]byte(`{"error":"invalid_grant","error_description":"Code not valid"}`))
		return
	}
	p.used[c] = true
	out := map[string]any{"access_token": "at-not-used", "token_type": "Bearer", "expires_in": 60}
	if !p.noToken {
		out["id_token"] = p.token
	}
	json.NewEncoder(w).Encode(out)
}

// allFresh are the four fresh methods, all switched on.
var allFresh = []string{"passkey_synced", "passkey_device", "security_key", "yubikey_cert"}

func (p *idp) verifier() *freshauth.Verifier {
	return p.verifierWith(func() []string { return allFresh })
}

// verifierWith is a verifier whose switched-on fresh methods are accepted().
func (p *idp) verifierWith(accepted func() []string) *freshauth.Verifier {
	base := p.srv.URL + "/realms/portcullis/protocol/openid-connect"
	return freshauth.New(freshauth.Config{
		Issuer:       issuer,
		TokenURL:     base + "/token",
		JWKSURL:      base + "/certs",
		AuthorizeURL: "https://auth.example.org/realms/portcullis/protocol/openid-connect/auth",
		RedirectURI:  redirect,
		HTTP:         p.srv.Client(),
		Now:          func() time.Time { return now },
		Accepted:     accepted,
	})
}

// claims is a valid fresh-auth ID token's claims for alice.
func claims() map[string]any {
	return map[string]any{
		"iss":                issuer,
		"sub":                "f0e1d2c3-0000-4000-8000-000000000001",
		"aud":                freshauth.ClientID,
		"azp":                freshauth.ClientID,
		"exp":                now.Add(5 * time.Minute).Unix(),
		"iat":                now.Add(-10 * time.Second).Unix(),
		"auth_time":          now.Add(-10 * time.Second).Unix(),
		"nonce":              nonce,
		"amr":                []string{"hwk"},
		"acr":                "1",
		"pc_fresh":           "security_key",
		"preferred_username": "alice",
	}
}

func sign(t *testing.T, alg jose.SignatureAlgorithm, key any, kid string, c map[string]any) string {
	t.Helper()
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: jose.JSONWebKey{Key: key, KeyID: kid}}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(c)
	jws, err := s.Sign(b)
	if err != nil {
		t.Fatal(err)
	}
	out, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func (p *idp) rs256(c map[string]any) string { return sign(p.t, jose.RS256, p.rsaKey, "rsa1", c) }

func proof() freshauth.Proof {
	return freshauth.Proof{Code: code, CodeVerifier: verifier, Nonce: nonce}
}

func TestFreshAuthAccepts(t *testing.T) {
	for _, tc := range []struct {
		name   string
		method string
		user   string
		ec     bool
		edit   func(map[string]any)
	}{
		{name: "security_key", method: "security_key", user: "alice"},
		{name: "passkey_synced", method: "passkey_synced", user: "alice"},
		{name: "passkey_device", method: "passkey_device", user: "alice"},
		{name: "yubikey_cert", method: "yubikey_cert", user: "alice"},
		// amr is never read: whatever the session accumulated.
		{name: "amr pwd only", method: "security_key", user: "alice", edit: func(c map[string]any) { c["amr"] = []string{"pwd"} }},
		{name: "no amr", method: "passkey_synced", user: "alice", edit: func(c map[string]any) { delete(c, "amr") }},
		{name: "case-folded username", method: "security_key", user: "alice", edit: func(c map[string]any) { c["preferred_username"] = "ALICE" }},
		{name: "caller case-folded", method: "security_key", user: "Alice"},
		{name: "ES256", method: "security_key", user: "alice", ec: true},
		{name: "aud list with azp", method: "security_key", user: "alice", edit: func(c map[string]any) { c["aud"] = []string{freshauth.ClientID, "account"} }},
		{name: "no azp, single aud", method: "security_key", user: "alice", edit: func(c map[string]any) { delete(c, "azp") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newIDP(t)
			c := claims()
			c["pc_fresh"] = tc.method
			if tc.edit != nil {
				tc.edit(c)
			}
			if tc.ec {
				p.token = sign(t, jose.ES256, p.ecKey, "ec1", c)
			} else {
				p.token = p.rs256(c)
			}
			res, err := p.verifier().Verify(context.Background(), proof(), tc.user)
			if err != nil {
				t.Fatalf("Verify: %v (%#v)", err, err)
			}
			if res.User != "alice" || !res.AuthTime.Equal(now.Add(-10*time.Second)) || res.Method != tc.method {
				t.Errorf("result = %+v", res)
			}
			// PKCE: the verifier went to the token endpoint with the code.
			if len(p.posted) != 1 || p.posted[0]["code_verifier"] != verifier || p.posted[0]["code"] != code {
				t.Errorf("posted = %v", p.posted)
			}
			for _, f := range p.posted {
				if _, ok := f["client_secret"]; ok {
					t.Errorf("a public client sends no secret: %v", f)
				}
			}
		})
	}
}

// TestFreshAuthRefusesSwitchedOffSecurityKey (D19, controller ruling):
// fresh auth reads only pc_fresh — the method of the authenticator that
// ran in this authentication — and only while that method is on; amr
// (accumulated over the SSO session) is never used.
func TestFreshAuthRefusesSwitchedOffSecurityKey(t *testing.T) {
	without := func(m string) func() []string {
		return func() []string {
			var out []string
			for _, x := range allFresh {
				if x != m {
					out = append(out, x)
				}
			}
			return out
		}
	}
	for _, tc := range []struct {
		name     string
		edit     func(map[string]any)
		accepted func() []string
		ok       bool
		reason   string
	}{
		{name: "security_key off", edit: func(c map[string]any) { c["pc_fresh"] = "security_key" }, accepted: without("security_key"), reason: "pc_fresh names a method that is switched off"},
		{name: "passkey_synced off", edit: func(c map[string]any) { c["pc_fresh"] = "passkey_synced" }, accepted: without("passkey_synced"), reason: "pc_fresh names a method that is switched off"},
		{name: "passkey_device off", edit: func(c map[string]any) { c["pc_fresh"] = "passkey_device" }, accepted: without("passkey_device"), reason: "pc_fresh names a method that is switched off"},
		{name: "yubikey_cert off", edit: func(c map[string]any) { c["pc_fresh"] = "yubikey_cert" }, accepted: without("yubikey_cert"), reason: "pc_fresh names a method that is switched off"},
		{name: "security_key on", edit: func(c map[string]any) { c["pc_fresh"] = "security_key" }, accepted: func() []string { return []string{"security_key"} }, ok: true},
		{name: "passkey_synced on", edit: func(c map[string]any) { c["pc_fresh"] = "passkey_synced" }, accepted: func() []string { return []string{"passkey_synced"} }, ok: true},
		{name: "passkey_device on", edit: func(c map[string]any) { c["pc_fresh"] = "passkey_device" }, accepted: func() []string { return []string{"passkey_device"} }, ok: true},
		{name: "yubikey_cert on", edit: func(c map[string]any) { c["pc_fresh"] = "yubikey_cert" }, accepted: func() []string { return []string{"yubikey_cert"} }, ok: true},
		{name: "missing pc_fresh", edit: func(c map[string]any) { delete(c, "pc_fresh") }, accepted: allFreshF, reason: "missing pc_fresh"},
		{name: "missing pc_fresh, amr hwk", edit: func(c map[string]any) { delete(c, "pc_fresh"); c["amr"] = []string{"hwk"} }, accepted: allFreshF, reason: "missing pc_fresh"},
		{name: "null pc_fresh", edit: func(c map[string]any) { c["pc_fresh"] = nil }, accepted: allFreshF, reason: "missing pc_fresh"},
		{name: "empty pc_fresh", edit: func(c map[string]any) { c["pc_fresh"] = "" }, accepted: allFreshF, reason: "missing pc_fresh"},
		{name: "pc_fresh a list", edit: func(c map[string]any) { c["pc_fresh"] = []string{"security_key"} }, accepted: allFreshF, reason: "missing pc_fresh"},
		{name: "pc_fresh a number", edit: func(c map[string]any) { c["pc_fresh"] = 3 }, accepted: allFreshF, reason: "missing pc_fresh"},
		{name: "pc_fresh password", edit: func(c map[string]any) { c["pc_fresh"] = "password" }, accepted: allFreshF, reason: "pc_fresh is not a passkey or a YubiKey certificate"},
		{name: "pc_fresh browser_cert", edit: func(c map[string]any) { c["pc_fresh"] = "browser_cert" }, accepted: allFreshF, reason: "pc_fresh is not a passkey or a YubiKey certificate"},
		{name: "pc_fresh inv", edit: func(c map[string]any) { c["pc_fresh"] = "inv" }, accepted: allFreshF, reason: "pc_fresh is not a passkey or a YubiKey certificate"},
		{name: "pc_fresh unknown", edit: func(c map[string]any) { c["pc_fresh"] = "retina" }, accepted: allFreshF, reason: "pc_fresh is not a passkey or a YubiKey certificate"},
		{name: "pc_fresh an amr value", edit: func(c map[string]any) { c["pc_fresh"] = "hwk" }, accepted: allFreshF, reason: "pc_fresh is not a passkey or a YubiKey certificate"},
		{name: "pc_fresh case variant", edit: func(c map[string]any) { c["pc_fresh"] = "Security_Key" }, accepted: allFreshF, reason: "pc_fresh is not a passkey or a YubiKey certificate"},
		// The session's amr carries an older hwk; this sign-in was a password.
		{name: "amr hwk, pc_fresh password", edit: func(c map[string]any) { c["amr"] = []string{"hwk", "pwd"}; c["pc_fresh"] = "password" }, accepted: allFreshF, reason: "pc_fresh is not a passkey or a YubiKey certificate"},
		{name: "amr mtls, pc_fresh missing", edit: func(c map[string]any) { c["amr"] = []string{"mtls"}; delete(c, "pc_fresh") }, accepted: allFreshF, reason: "missing pc_fresh"},
		// Whatever Accepted returns: never a password, a browser
		// certificate or a setup link.
		{name: "password accepted by mistake", edit: func(c map[string]any) { c["pc_fresh"] = "password" }, accepted: func() []string { return []string{"password", "browser_cert", "inv"} }, reason: "pc_fresh is not a passkey or a YubiKey certificate"},
		{name: "browser_cert accepted by mistake", edit: func(c map[string]any) { c["pc_fresh"] = "browser_cert" }, accepted: func() []string { return []string{"browser_cert"} }, reason: "pc_fresh is not a passkey or a YubiKey certificate"},
		{name: "nothing on", accepted: func() []string { return nil }, reason: "pc_fresh names a method that is switched off"},
		{name: "no Accepted", accepted: nil, reason: "pc_fresh names a method that is switched off"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newIDP(t)
			c := claims()
			if tc.edit != nil {
				tc.edit(c)
			}
			p.token = p.rs256(c)
			res, err := p.verifierWith(tc.accepted).Verify(context.Background(), proof(), "alice")
			if tc.ok {
				if err != nil || res == nil || res.Method != c["pc_fresh"] {
					t.Fatalf("Verify = %+v, %v; want accepted", res, err)
				}
				return
			}
			var fe *freshauth.Error
			if !errors.As(err, &fe) || res != nil {
				t.Fatalf("Verify = %+v, %v; want *freshauth.Error", res, err)
			}
			if fe.Reason != tc.reason || err.Error() != freshauth.Message {
				t.Errorf("reason %q (%q), want %q", fe.Reason, err.Error(), tc.reason)
			}
		})
	}
}

func allFreshF() []string { return allFresh }

func TestFreshAuthRefusals(t *testing.T) {
	type tcase struct {
		name  string
		edit  func(map[string]any)
		token func(p *idp, c map[string]any) string // nil: RS256 by the realm key
		proof func(freshauth.Proof) freshauth.Proof
		user  string
		setup func(p *idp, v *freshauth.Verifier)
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	cases := []tcase{
		{name: "stale auth_time", edit: func(c map[string]any) { c["auth_time"] = now.Add(-301 * time.Second).Unix() }},
		{name: "missing auth_time", edit: func(c map[string]any) { delete(c, "auth_time") }},
		{name: "future auth_time", edit: func(c map[string]any) { c["auth_time"] = now.Add(2 * time.Minute).Unix() }},
		{name: "acr file", edit: func(c map[string]any) { c["acr"] = "file" }},
		{name: "wrong nonce", edit: func(c map[string]any) { c["nonce"] = "nonce-other" }},
		{name: "missing nonce in token", edit: func(c map[string]any) { delete(c, "nonce") }},
		{name: "missing nonce in proof", edit: func(c map[string]any) { c["nonce"] = "" }, proof: func(p freshauth.Proof) freshauth.Proof { p.Nonce = ""; return p }},
		{name: "azp another client", edit: func(c map[string]any) { c["azp"] = "portcullis-forward-auth" }},
		{name: "aud without the client", edit: func(c map[string]any) { c["aud"] = "account"; delete(c, "azp") }},
		{name: "aud without the client but azp", edit: func(c map[string]any) { c["aud"] = "account" }},
		{name: "several aud without azp", edit: func(c map[string]any) { c["aud"] = []string{freshauth.ClientID, "account"}; delete(c, "azp") }},
		{name: "wrong issuer", edit: func(c map[string]any) { c["iss"] = "http://keycloak:8080/realms/portcullis" }},
		{name: "expired", edit: func(c map[string]any) { c["exp"] = now.Add(-time.Second).Unix() }},
		{name: "no exp", edit: func(c map[string]any) { delete(c, "exp") }},
		{name: "iat in the future", edit: func(c map[string]any) { c["iat"] = now.Add(61 * time.Second).Unix() }},
		{name: "missing iat", edit: func(c map[string]any) { delete(c, "iat") }},
		{name: "wrong username", edit: func(c map[string]any) { c["preferred_username"] = "bob" }},
		{name: "missing username", edit: func(c map[string]any) { delete(c, "preferred_username") }},
		{name: "missing sub", edit: func(c map[string]any) { delete(c, "sub") }},
		{name: "empty caller", user: "-"},
		{name: "another key", token: func(p *idp, c map[string]any) string { return sign(p.t, jose.RS256, other, "rsa1", c) }},
		{name: "unknown kid", token: func(p *idp, c map[string]any) string { return sign(p.t, jose.RS256, other, "rsa9", c) }},
		{name: "RS512", token: func(p *idp, c map[string]any) string { return sign(p.t, jose.RS512, p.rsaKey, "rsa1", c) }},
		{name: "PS256", token: func(p *idp, c map[string]any) string { return sign(p.t, jose.PS256, p.rsaKey, "rsa1", c) }},
		// The classic key-confusion attack: HMAC "signed" with the realm's
		// public RSA key (as DER and as PEM) under its kid, hoping the
		// verifier uses the public key as the HMAC secret.
		{name: "HS256 with the public key DER", token: func(p *idp, c map[string]any) string {
			return sign(p.t, jose.HS256, publicDER(p.t, &p.rsaKey.PublicKey), "rsa1", c)
		}},
		{name: "HS256 with the public key PEM", token: func(p *idp, c map[string]any) string {
			der := publicDER(p.t, &p.rsaKey.PublicKey)
			return sign(p.t, jose.HS256, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), "rsa1", c)
		}},
		{name: "alg none", token: func(p *idp, c map[string]any) string {
			b, _ := json.Marshal(c)
			enc := base64.RawURLEncoding.EncodeToString
			return enc([]byte(`{"alg":"none","typ":"JWT"}`)) + "." + enc(b) + "."
		}},
		{name: "not a jwt", token: func(*idp, map[string]any) string { return "garbage" }},
		{name: "no id_token", setup: func(p *idp, _ *freshauth.Verifier) { p.noToken = true }},
		{name: "replayed code", setup: func(p *idp, v *freshauth.Verifier) {
			if _, err := v.Verify(context.Background(), proof(), "alice"); err != nil {
				p.t.Fatalf("first use: %v", err)
			}
		}},
		{name: "wrong verifier", proof: func(p freshauth.Proof) freshauth.Proof {
			p.CodeVerifier = "verifier-wrong-AbCdEfGhIjKlMnOpQrStUvWxYz012345678"
			return p
		}},
		{name: "empty code", proof: func(p freshauth.Proof) freshauth.Proof { p.Code = ""; return p }},
		{name: "empty verifier", proof: func(p freshauth.Proof) freshauth.Proof { p.CodeVerifier = ""; return p }},
		{name: "short verifier", proof: func(p freshauth.Proof) freshauth.Proof { p.CodeVerifier = "short"; return p }},
		{name: "verifier bad charset", proof: func(p freshauth.Proof) freshauth.Proof { p.CodeVerifier = strings.Repeat("a", 42) + "+"; return p }},
		{name: "oversized code", proof: func(p freshauth.Proof) freshauth.Proof { p.Code = strings.Repeat("c", 5000); return p }},
	}
	// wantReason: the audit reason of each case (fixed strings).
	wantReason := map[string]string{
		"stale auth_time":                "sign-in older than 5 minutes",
		"missing auth_time":              "missing auth_time",
		"future auth_time":               "auth_time in the future",
		"acr file":                       "acr contains file",
		"wrong nonce":                    "nonce mismatch",
		"missing nonce in token":         "missing nonce in the id token",
		"missing nonce in proof":         "missing or oversized nonce",
		"azp another client":             "azp is another client",
		"aud without the client":         "id token audience is not the fresh-auth client",
		"aud without the client but azp": "id token audience is not the fresh-auth client",
		"several aud without azp":        "several audiences without azp",
		"wrong issuer":                   "id token from another issuer",
		"expired":                        "id token expired",
		"no exp":                         "id token expired",
		"iat in the future":              "iat in the future",
		"missing iat":                    "missing iat",
		"wrong username":                 "signed in as another person",
		"missing username":               "missing preferred_username",
		"missing sub":                    "missing sub",
		"empty caller":                   "no caller",
		"another key":                    "id token signature not verified by the realm's keys",
		"unknown kid":                    "id token signature not verified by the realm's keys",
		"RS512":                          "id token malformed or signed with an unsupported algorithm",
		"PS256":                          "id token malformed or signed with an unsupported algorithm",
		"HS256 with the public key DER":  "id token malformed or signed with an unsupported algorithm",
		"HS256 with the public key PEM":  "id token malformed or signed with an unsupported algorithm",
		"alg none":                       "id token malformed or signed with an unsupported algorithm",
		"not a jwt":                      "id token malformed or signed with an unsupported algorithm",
		"no id_token":                    "no id token in the token response",
		"replayed code":                  "code exchange refused: invalid_grant (expired, replayed or wrong verifier)",
		"wrong verifier":                 "code exchange refused: invalid_grant (expired, replayed or wrong verifier)",
		"empty code":                     "missing or oversized code",
		"empty verifier":                 "malformed code verifier",
		"short verifier":                 "malformed code verifier",
		"verifier bad charset":           "malformed code verifier",
		"oversized code":                 "missing or oversized code",
	}
	if len(wantReason) != len(cases) {
		t.Fatalf("%d reasons for %d cases", len(wantReason), len(cases))
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newIDP(t)
			c := claims()
			if tc.edit != nil {
				tc.edit(c)
			}
			if tc.token != nil {
				p.token = tc.token(p, c)
			} else {
				p.token = p.rs256(c)
			}
			v := p.verifier()
			if tc.setup != nil {
				tc.setup(p, v)
			}
			pr := proof()
			if tc.proof != nil {
				pr = tc.proof(pr)
			}
			user := "alice"
			if tc.user == "-" {
				user = ""
			} else if tc.user != "" {
				user = tc.user
			}
			res, err := v.Verify(context.Background(), pr, user)
			var fe *freshauth.Error
			if !errors.As(err, &fe) || res != nil {
				t.Fatalf("Verify = %+v, %v; want *freshauth.Error", res, err)
			}
			if err.Error() != freshauth.Message || freshauth.Message != "a fresh passkey sign-in is required" || fe.Status() != http.StatusForbidden {
				t.Errorf("answer %d %q, want 403 with the generic text", fe.Status(), err.Error())
			}
			if fe.Reason != wantReason[tc.name] {
				t.Errorf("reason %q, want %q", fe.Reason, wantReason[tc.name])
			}
			for _, s := range []string{code, verifier, nonce, p.token} {
				if s != "" && strings.Contains(fe.Reason, s) {
					t.Errorf("reason %q carries a proof value", fe.Reason)
				}
			}
		})
	}
}

func TestFreshAuthNeverLogsCode(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	p := newIDP(t)
	p.token = p.rs256(claims())
	v := p.verifier()
	var texts []string
	if _, err := v.Verify(context.Background(), proof(), "alice"); err != nil {
		t.Fatal(err)
	}
	// Replay, a wrong user, a bad token: every refusal's text and reason.
	for _, f := range []func(){
		func() {},
		func() {
			p.used = map[string]bool{}
			c := claims()
			c["preferred_username"] = "bob"
			p.token = p.rs256(c)
		},
		func() { p.used = map[string]bool{}; p.token = "x." + p.token },
	} {
		f()
		_, err := v.Verify(context.Background(), proof(), "alice")
		var fe *freshauth.Error
		if !errors.As(err, &fe) {
			t.Fatalf("want a refusal, got %v", err)
		}
		texts = append(texts, err.Error(), fe.Reason)
	}
	texts = append(texts, buf.String())
	all := strings.Join(texts, "\n")
	for _, s := range []string{code, verifier, nonce, p.token, strings.Split(p.token, ".")[1]} {
		if strings.Contains(all, s) {
			t.Errorf("logs/errors carry %q:\n%s", s, all)
		}
	}
}

func TestFreshAuthInfo(t *testing.T) {
	p := newIDP(t)
	info := p.verifier().Info()
	b, _ := json.Marshal(info)
	want := `{"authorize_url":"https://auth.example.org/realms/portcullis/protocol/openid-connect/auth","client_id":"portcullis-fresh-auth","redirect_uri":"https://people.example.org/"}`
	if string(b) != want {
		t.Errorf("Info = %s", b)
	}
	if freshauth.MaxAge != 5*time.Minute || strings.Join(freshauth.FreshMethods, ",") != "passkey_synced,passkey_device,security_key,yubikey_cert" {
		t.Errorf("MaxAge %v FreshMethods %v", freshauth.MaxAge, freshauth.FreshMethods)
	}
}

func TestFreshAuthNotConfigured(t *testing.T) {
	v := freshauth.New(freshauth.Config{})
	_, err := v.Verify(context.Background(), proof(), "alice")
	var fe *freshauth.Error
	if !errors.As(err, &fe) {
		t.Fatalf("unconfigured verifier: %v", err)
	}
}

func publicDER(t *testing.T, k *rsa.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// N3: the realm's keys can't be fetched (JWKS at a closed port) — a
// Hub-side outage: ReasonUnreachable (the Hub answers 503, not counted),
// never "signature not verified".
func TestJWKSUnreachableIsUnreachable(t *testing.T) {
	p := newIDP(t)
	p.token = p.rs256(claims())
	closed := httptest.NewServer(http.NotFoundHandler())
	dead := closed.URL + "/certs"
	closed.Close()
	base := p.srv.URL + "/realms/portcullis/protocol/openid-connect"
	v := freshauth.New(freshauth.Config{
		Issuer: issuer, TokenURL: base + "/token", JWKSURL: dead,
		AuthorizeURL: "https://auth.example.org/realms/portcullis/protocol/openid-connect/auth",
		RedirectURI:  redirect, HTTP: p.srv.Client(), Now: func() time.Time { return now },
	})
	_, err := v.Verify(context.Background(), proof(), "alice")
	var fe *freshauth.Error
	if !errors.As(err, &fe) || fe.Reason != freshauth.ReasonUnreachable {
		t.Fatalf("JWKS unreachable = %v (%+v), want reason %q", err, fe, freshauth.ReasonUnreachable)
	}
}
