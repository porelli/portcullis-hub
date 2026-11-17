// Package login is `portcullis login` (contract §18.15): discovery, the
// PKCE loopback sign-in in the person's browser, an ephemeral ed25519 key
// (or --key through the agent), the SSHSIG key proof, the certificate
// request, the agent, and the SSH files. The CLI never calls Keycloak's
// token endpoint: the Hub exchanges the code.
package login

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/hiddeco/sshsig"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/oauth2"

	"github.com/portcullis/hub/cmd/portcullis/internal/agentx"
	"github.com/portcullis/hub/cmd/portcullis/internal/api"
	"github.com/portcullis/hub/cmd/portcullis/internal/config"
	"github.com/portcullis/hub/cmd/portcullis/internal/loopback"
	"github.com/portcullis/hub/cmd/portcullis/internal/sshconf"
	"github.com/portcullis/hub/internal/cliapi"
)

// Methods are the --method values (the sign-in method ids).
var Methods = []string{"password", "totp", "passkey_synced", "browser_cert", "passkey_device", "security_key", "yubikey_cert"}

// Options are login's flags and its environment.
type Options struct {
	Domain     string
	Method     string
	KeyFile    string
	WriteFiles bool
	NoBrowser  bool
	CAFile     string
	Debug      io.Writer
	Version    string
	Home       string
	ConfigDir  string
	Stdout     io.Writer
	Stderr     io.Writer
	HostGroups []string

	// Test hooks (no flags): the people URL ("" = https://people.<d>),
	// the browser, the agent, the HTTP client, the clock, and an
	// authorize URL host other than auth.<d>.
	PeopleURL          string
	OpenBrowser        func(string) error
	Agent              func() (agent.ExtendedAgent, func(), error)
	HTTP               *http.Client
	Now                func() time.Time
	AllowAuthorizeHost string
}

func (o *Options) defaults() {
	if o.Stdout == nil {
		o.Stdout = os.Stdout
	}
	if o.Stderr == nil {
		o.Stderr = os.Stderr
	}
	if o.Agent == nil {
		o.Agent = agentx.Open
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Home == "" {
		o.Home, _ = os.UserHomeDir()
	}
}

// Client is the API client for o's domain.
func (o *Options) Client(caFile string) (*api.Client, error) {
	base := o.PeopleURL
	if base == "" {
		base = "https://people." + o.Domain
	}
	c, err := api.New(base, o.Version, caFile)
	if err != nil {
		return nil, api.Errorf(api.ExitUsage, "%v", err)
	}
	if o.HTTP != nil {
		c.HTTP = o.HTTP
	}
	c.Debug = o.Debug
	return c, nil
}

// Discover reads and checks the server's public config.
func Discover(ctx context.Context, o *Options, c *api.Client) (*cliapi.Config, error) {
	var cfg cliapi.Config
	if _, err := c.Do(ctx, http.MethodGet, "/api/cli/v1/config", nil, &cfg, nil); err != nil {
		return nil, err
	}
	au, err := url.Parse(cfg.AuthorizeURL)
	wantHost := "auth." + o.Domain
	if o.AllowAuthorizeHost != "" {
		wantHost = o.AllowAuthorizeHost
	}
	switch {
	case cfg.API != cliapi.APIVersion:
		return nil, api.Errorf(api.ExitError, "the server speaks CLI API %d, this CLI %d: update the Portcullis CLI", cfg.API, cliapi.APIVersion)
	case cfg.ClientID != cliapi.ClientID || cfg.Domain != o.Domain:
		return nil, api.Errorf(api.ExitError, "%s didn't answer as a Portcullis server for %s", c.Base, o.Domain)
	case !slices.Equal(cfg.RedirectPorts, cliapi.RedirectPorts[:]):
		return nil, api.Errorf(api.ExitError, "the server's sign-in ports differ from this CLI's: update the Portcullis CLI")
	case err != nil || au.Scheme != "https" || au.Host != wantHost || au.User != nil || au.RawQuery != "" || au.Fragment != "":
		return nil, api.Errorf(api.ExitError, "the server's sign-in address isn't https://%s/…: refusing", wantHost)
	}
	return &cfg, nil
}

// SignIn is one loopback sign-in: the code, its PKCE verifier, the nonce
// and the redirect URI. Nothing of it is printed.
type SignIn struct {
	Code, Verifier, Nonce, RedirectURI string
}

func random() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// AuthorizeURL is the authorize request for a loopback redirect.
func AuthorizeURL(cfg *cliapi.Config, redirect, state, nonce, verifier, method string) string {
	oc := oauth2.Config{ClientID: cliapi.ClientID, RedirectURL: redirect, Scopes: []string{"openid"},
		Endpoint: oauth2.Endpoint{AuthURL: cfg.AuthorizeURL}}
	opts := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("prompt", "login"), oauth2.SetAuthURLParam("max_age", "0")}
	if method != "" {
		opts = append(opts, oauth2.SetAuthURLParam("pc_method", method))
	}
	return oc.AuthCodeURL(state, opts...)
}

// DoSignIn runs the browser half.
func DoSignIn(ctx context.Context, o *Options, cfg *cliapi.Config) (*SignIn, error) {
	if o.Method != "" && !slices.Contains(Methods, o.Method) {
		return nil, api.Errorf(api.ExitUsage, "--method must be one of %s", strings.Join(Methods, ", "))
	}
	l, err := loopback.Listen(ctx)
	if err != nil {
		return nil, api.Errorf(api.ExitError, "%v", err)
	}
	verifier, state, nonce := oauth2.GenerateVerifier(), random(), random()
	u := AuthorizeURL(cfg, l.RedirectURI(), state, nonce, verifier, o.Method)
	if o.NoBrowser || o.OpenBrowser == nil {
		fmt.Fprintf(o.Stderr, "Open this address in a browser on this computer to sign in:\n\n  %s\n\n", u)
	} else {
		fmt.Fprintf(o.Stderr, "Opening your browser to sign in to %s…\n", o.Domain)
		if err := o.OpenBrowser(u); err != nil {
			fmt.Fprintf(o.Stderr, "Couldn't open a browser: open this address on this computer:\n\n  %s\n\n", u)
		}
	}
	code, err := l.Wait(ctx, state)
	if err != nil {
		return nil, api.Errorf(api.ExitError, "%v", err)
	}
	return &SignIn{Code: code, Verifier: verifier, Nonce: nonce, RedirectURI: l.RedirectURI()}, nil
}

// key is the key to certify: an ephemeral one (priv set) or the
// person's own in the agent (--key).
type key struct {
	signer ssh.Signer
	priv   ed25519.PrivateKey
	norm   string
}

// Result is a finished login.
type Result struct {
	Answer *cliapi.CertAnswer
	Notes  []string
}

// Run is portcullis login.
func Run(ctx context.Context, o Options) (*Result, error) {
	o.defaults()
	if !cliapi.ValidDomain(o.Domain) {
		return nil, api.Errorf(api.ExitUsage, "%q isn't a domain: portcullis login <domain>, e.g. portcullis login example.com", api.Printable(o.Domain))
	}
	if o.Method != "" && !slices.Contains(Methods, o.Method) {
		return nil, api.Errorf(api.ExitUsage, "--method must be one of %s", strings.Join(Methods, ", "))
	}
	f, err := config.Load(o.ConfigDir)
	if err != nil {
		return nil, err
	}
	caFile := o.CAFile
	if caFile == "" {
		caFile = os.Getenv("PORTCULLIS_CA_FILE")
	}
	if caFile == "" {
		caFile = f.Domains[o.Domain].CAFile
	}
	// The agent first: no agent and no --write-files is refused before
	// anyone signs in.
	ag, closeAg, aerr := o.Agent()
	if aerr != nil && (o.KeyFile != "" || !o.WriteFiles) {
		return nil, api.Errorf(api.ExitError, "%v", aerr)
	}
	if closeAg != nil {
		defer closeAg()
	}
	k, err := chooseKey(o, ag)
	if err != nil {
		return nil, err
	}
	c, err := o.Client(caFile)
	if err != nil {
		return nil, err
	}
	cfg, err := Discover(ctx, &o, c)
	if err != nil {
		return nil, err
	}
	si, err := DoSignIn(ctx, &o, cfg)
	if err != nil {
		return nil, err
	}
	sig, err := sshsig.Sign(bytes.NewReader(cliapi.KeyProofMessage(o.Domain, si.Nonce, si.Code, k.norm)), k.signer, sshsig.HashSHA512, cliapi.NSKeyProof)
	if err != nil {
		return nil, api.Errorf(api.ExitError, "signing the key proof failed (a FIDO key needs a touch): %v", err)
	}
	groups := o.HostGroups
	if groups == nil {
		groups = []string{}
	}
	req := cliapi.CertRequest{Code: si.Code, CodeVerifier: si.Verifier, Nonce: si.Nonce, RedirectURI: si.RedirectURI,
		PublicKey: k.norm, KeyProof: string(sshsig.Armor(sig)), HostGroups: groups, OwnKey: k.priv == nil}
	var ans cliapi.CertAnswer
	if _, err := c.Do(ctx, http.MethodPost, "/api/cli/v1/ssh/certificates", req, &ans, nil); err != nil {
		return nil, err
	}
	res := &Result{Answer: &ans}
	for _, r := range ans.Refused {
		fmt.Fprintf(o.Stderr, "%s: %s\n", api.Printable(r.HostGroup), api.Printable(r.Reason))
	}
	if len(ans.Certificates) == 0 {
		return res, api.Errorf(api.ExitNoCert, "signed in as %s, but no SSH certificate was issued", api.Printable(ans.User))
	}
	entries, err := checkAnswer(&ans, k)
	if err != nil {
		return nil, err
	}
	if ag != nil && k.priv != nil {
		notes, err := agentx.ReplaceDomain(ag, o.Domain, entries, o.Now())
		res.Notes = append(res.Notes, notes...)
		if err != nil {
			return res, api.Errorf(api.ExitError, "%v", err)
		}
	}
	var privPEM []byte
	if o.WriteFiles && k.priv != nil {
		blk, err := ssh.MarshalPrivateKey(k.priv, "portcullis "+o.Domain)
		if err != nil {
			return res, err
		}
		privPEM = pem.EncodeToMemory(blk)
	}
	if err := sshconf.Write(o.Home, o.Domain, &ans, k.norm, privPEM); err != nil {
		return res, api.Errorf(api.ExitError, "writing ~/.ssh/portcullis: %v", err)
	}
	d := f.Domains[o.Domain]
	d.Config = *cfg
	if o.CAFile != "" {
		d.CAFile = o.CAFile
	}
	f.Domains[o.Domain] = d
	if f.Default == "" {
		f.Default = o.Domain
	}
	if err := f.Save(o.ConfigDir); err != nil {
		res.Notes = append(res.Notes, "couldn't save the CLI's settings: "+err.Error())
	}
	for _, cert := range ans.Certificates {
		fmt.Fprintf(o.Stdout, "%s: %s until %s\n", cert.HostGroup, strings.Join(cert.Principals, ", "), cert.ValidBefore.Local().Format("Mon 15:04"))
	}
	for _, n := range res.Notes {
		fmt.Fprintln(o.Stderr, n)
	}
	if !sshconf.Installed(o.Home) {
		fmt.Fprintln(o.Stderr, "Run portcullis ssh-config --install once so ssh uses these certificates.")
	}
	return res, nil
}

func chooseKey(o Options, ag agent.ExtendedAgent) (*key, error) {
	if o.KeyFile != "" {
		raw, err := os.ReadFile(o.KeyFile)
		if err != nil {
			return nil, api.Errorf(api.ExitUsage, "--key: %v", err)
		}
		pub, norm, err := cliapi.ParseAuthorizedKey(strings.TrimSpace(string(raw)))
		if err != nil {
			return nil, api.Errorf(api.ExitUsage, "--key must be a public key file (.pub)")
		}
		if !cliapi.AcceptedKeyType(pub.Type(), cliapi.SKKeysAccepted) {
			return nil, api.Errorf(api.ExitUsage, "--key: %s keys can't be certified: use an ed25519, ECDSA P-256 or FIDO (sk-) key", pub.Type())
		}
		s, err := agentx.Signer(ag, pub)
		if err != nil {
			return nil, api.Errorf(api.ExitError, "%v", err)
		}
		return &key{signer: s, norm: norm}, nil
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, err
	}
	return &key{signer: s, priv: priv, norm: cliapi.NormalAuthorizedKey(s.PublicKey())}, nil
}

// checkAnswer: every certificate is a user certificate for our key, with
// the principals and a key id the answer names.
func checkAnswer(ans *cliapi.CertAnswer, k *key) ([]agentx.Entry, error) {
	var out []agentx.Entry
	want := k.signer.PublicKey().Marshal()
	for _, ic := range ans.Certificates {
		c, err := sshconf.ParseCert(ic.Certificate)
		if err != nil || c.CertType != ssh.UserCert || !bytes.Equal(c.Key.Marshal(), want) || !slices.Equal(c.ValidPrincipals, ic.Principals) ||
			!strings.HasPrefix(c.KeyId, "pc:"+ans.User+":"+ic.HostGroup+":") || !cliapi.ValidHostGroupID(ic.HostGroup) {
			return nil, api.Errorf(api.ExitError, "the server answered a %s certificate that isn't for this key: nothing was loaded", api.Printable(ic.HostGroup))
		}
		out = append(out, agentx.Entry{HostGroup: ic.HostGroup, Key: k.priv, Certificate: c})
	}
	return out, nil
}

// ErrSilence is returned when a command printed its own message.
var ErrSilence = errors.New("")
