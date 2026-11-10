// Command hub is the Portcullis Hub: a web UI that manages per-app docker
// compose projects for the Portcullis auth gateway.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/portcullis/hub/internal/compose"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/domains"
	"github.com/portcullis/hub/internal/folderfix"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/fsutil"
	"github.com/portcullis/hub/internal/httpapi"
	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/invite"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/lldap"
	"github.com/portcullis/hub/internal/signinreset"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/web"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// openDirectoryStore returns the store of directory.yaml under dataDir
// after loading it once: a corrupt file (or an unknown version) is an
// error, so the Hub refuses to start rather than run without its rules,
// exceptions, expiries and permissions. A missing file is fine (empty).
func openDirectoryStore(dataDir string) (*directory.Store, error) {
	st := &directory.Store{Path: filepath.Join(dataDir, "directory.yaml")}
	if _, err := st.Load(); err != nil {
		return nil, fmt.Errorf("directory.yaml is unreadable (fix or restore it; the Hub won't run without its rules and expiries): %w", err)
	}
	return st, nil
}

// fixerImageFromEnv is HUB_FIXER_IMAGE, honoured only with HUB_DEV=1 (contract
// §6, ruling 37): the shared-folder fixer runs as root with file
// capabilities, so outside development an env-selected image is refused
// (the Hub then uses its own image ID). New checks it is pinned by digest.
func fixerImageFromEnv(getenv func(string) string) (string, error) {
	v := getenv("HUB_FIXER_IMAGE")
	if v == "" {
		return "", nil
	}
	if getenv("HUB_DEV") != "1" {
		return "", fmt.Errorf("HUB_FIXER_IMAGE is for development only: set HUB_DEV=1 or unset it")
	}
	return v, nil
}

// freshAuthSetup is the fresh-auth wiring (contract §8): the issuer and
// authorize endpoint are public (HUB_KEYCLOAK_PUBLIC_URL, default
// https://auth.<domain>: Keycloak runs with that --hostname, so it is the
// tokens' iss), the code exchange and keys go to Keycloak internally
// (KEYCLOAK_URL). The popup lands on the listener that started it:
// https://people.<domain>/ (My apps, people confirmations) or
// https://hub.<domain>/ (admin confirmations, G11): one verifier each.
type freshAuthSetup struct {
	Issuer, TokenURL, JWKSURL, AuthorizeURL, RedirectURI, WebOrigin string
	HubRedirectURI, HubWebOrigin                                    string
}

func freshAuthFromEnv(getenv func(string) string, domain, keycloakURL string) (freshAuthSetup, error) {
	pub := getenv("HUB_KEYCLOAK_PUBLIC_URL")
	if pub == "" {
		pub = "https://auth." + domain
	}
	u, err := url.Parse(pub)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return freshAuthSetup{}, fmt.Errorf("HUB_KEYCLOAK_PUBLIC_URL must be https://<host> (Keycloak's public URL), got %q", pub)
	}
	public := "https://" + u.Host + "/realms/" + keycloak.Realm
	internal := strings.TrimRight(keycloakURL, "/") + "/realms/" + keycloak.Realm + "/protocol/openid-connect"
	return freshAuthSetup{
		Issuer:         public,
		TokenURL:       internal + "/token",
		JWKSURL:        internal + "/certs",
		AuthorizeURL:   public + "/protocol/openid-connect/auth",
		RedirectURI:    "https://people." + domain + "/",
		WebOrigin:      "https://people." + domain,
		HubRedirectURI: "https://hub." + domain + "/",
		HubWebOrigin:   "https://hub." + domain,
	}, nil
}

func main() {
	// `hub folderfix …`: the shared-folder fixer, run by the Hub in a helper
	// container (contract §6). First, before any Hub configuration is read.
	if len(os.Args) > 1 && os.Args[1] == "folderfix" {
		os.Exit(folderfix.Main(os.Args[2:], os.Stdout, os.Stderr))
	}
	// `hub signin reset-core`: the CLI's lockout recovery (contract §8.1),
	// run against the data directory while the Hub is stopped. Before the
	// Hub's configuration is read: only the data directory is needed.
	if len(os.Args) > 1 && os.Args[1] == "signin" {
		os.Exit(signinreset.Main(os.Args[2:], env("HUB_DATA_DIR", filepath.Join(env("PROJECT_DIR", "/project"), ".hub")), os.Stdout))
	}
	// SIGHUP = sync the template sources. Registered first: a SIGHUP that
	// arrives during start-up waits (Go's default would end the process).
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)

	secret := os.Getenv("HUB_PROXY_SECRET")
	if err := httpapi.CheckSecret(secret); err != nil {
		log.Fatalf("refusing to start: %v", err)
	}

	// The MCP listener's secret (contract §15.7): read once, here. A
	// missing file = no listener and AI support off; a short or
	// unreadable one refuses the start. Never logged.
	mcp, err := mcpListenerFromEnv(os.Getenv)
	if err != nil {
		log.Fatalf("refusing to start: %v", err)
	}

	projectDir := env("PROJECT_DIR", "/project")
	cfg := hub.Config{
		ProjectDir:          projectDir,
		ProjectHostDir:      env("PROJECT_HOST_DIR", projectDir),
		DataDir:             env("HUB_DATA_DIR", filepath.Join(projectDir, ".hub")),
		Domain:              env("PORTCULLIS_DOMAIN", "portcullis.local"),
		DefaultTemplatesURL: os.Getenv("DEFAULT_TEMPLATES_URL"),
		OverrideBindRoots:   os.Getenv("HUB_OVERRIDE_BIND_ROOTS"),
		// Settings data files (contract §13.7): default
		// <PROJECT_DIR>/appfiles (core mounts ./appfiles there), bind-mounted
		// from <PROJECT_HOST_DIR>/appfiles. HUB_APPFILES_DIR moves them and
		// needs HUB_APPFILES_HOST_DIR (the daemon's path): one without the
		// other refuses to start.
		AppFilesDir:     os.Getenv("HUB_APPFILES_DIR"),
		AppFilesHostDir: os.Getenv("HUB_APPFILES_HOST_DIR"),
		// Template sources are fast-forwarded at every start (fail-safe:
		// a failed pull keeps the previous checkout); "false" turns it off.
		SyncSourcesAtStart: os.Getenv("HUB_SYNC_SOURCES_AT_START") != "false",
		// Per-person password hashes (contract §6, §13.16): core's
		// hub_secrets volume at /secrets. Checked in New (owner = the
		// Hub's uid, 0700); unusable = those apps refuse to start.
		SecretsDir:    env("HUB_SECRETS_DIR", "/secrets"),
		SecretsVolume: env("HUB_SECRETS_VOLUME", hub.DefaultSecretsVolume),
		// The gate's age recipient (contract §15.4): readable = the core
		// has an mcp-gate (Settings → AI gate_present).
		MCPGateRecipientFile: env("HUB_MCP_GATE_RECIPIENT_FILE", "/run/portcullis/mcp-gate/age.pub"),
		MCPListener:          mcp.on,
		MCPGateDataDir:       env("HUB_MCP_GATE_DATA_DIR", "/mcp-gate-data"),
	}
	fixerImage, err := fixerImageFromEnv(os.Getenv)
	if err != nil {
		log.Fatalf("refusing to start: %v", err)
	}
	cfg.FixerImage = fixerImage
	if v := os.Getenv("HUB_RECONCILE_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < 5*time.Second {
			log.Fatalf("HUB_RECONCILE_INTERVAL must be a duration >= 5s, got %q", v)
		}
		cfg.ReconcileInterval = d
	}

	dockerHost := env("DOCKER_HOST", docker.DefaultHost)
	engine, err := docker.New(dockerHost)
	if err != nil {
		log.Fatalf("refusing to start: %v", err)
	}
	keycloakURL := env("KEYCLOAK_URL", "http://keycloak:8080")
	kc := keycloak.New(keycloakURL, os.Getenv("KEYCLOAK_ADMIN"), os.Getenv("KEYCLOAK_ADMIN_PASSWORD"))
	fa, err := freshAuthFromEnv(os.Getenv, cfg.Domain, keycloakURL)
	if err != nil {
		log.Fatalf("refusing to start: %v", err)
	}

	cli := compose.NewCLI(dockerHost)
	if v, err := cli.Version(context.Background()); err != nil {
		log.Fatalf("refusing to start: %v", err)
	} else if err := compose.CheckVersion(v); err != nil {
		log.Fatalf("refusing to start: %v", err)
	}
	// The data directory's advisory lock, held while the Hub runs: `hub
	// signin reset-core` refuses to edit state.yaml under a running Hub
	// (and a second Hub on the same data refuses to start).
	if err := os.MkdirAll(cfg.DataDir, 0755); err != nil {
		log.Fatalf("refusing to start: %v", err)
	}
	releaseLock, err := fsutil.TryLock(filepath.Join(cfg.DataDir, state.LockFile))
	if err != nil {
		log.Fatalf("refusing to start: the data directory is in use (another Hub, or signin reset-core running?): %v", err)
	}
	defer releaseLock()
	h, err := hub.New(cfg, cli, engine, kc)
	if err != nil {
		log.Fatalf("refusing to start: %v", err)
	}

	// User & group management (contract §9). Credentials are files core
	// mounts read-only, never env vars; without them the Users page says so
	// and the rest of the Hub works as before.
	ll := lldap.New(
		env("LLDAP_HTTP_URL", "http://lldap:17170"),
		env("LLDAP_LDAP_URL", "ldap://lldap:3890"),
		env("LLDAP_BASE_DN", "dc=portcullis,dc=local"),
		env("HUB_LLDAP_CREDENTIALS_DIR", lldap.DefaultCredentialsDir),
	)
	if err := ll.Available(); err != nil {
		log.Printf("users & groups disabled: %v", err)
	}
	invites := invite.New(env("HUB_INVITE_API_URL", invite.DefaultAPIURL), env("HUB_INVITE_SECRET_FILE", invite.DefaultSecretFile))
	if err := invites.Available(); err != nil {
		log.Printf("invite links disabled (password fallback only): %v", err)
	}
	// Enrolled domains (contract §12): core's domains service, bearer secret
	// from a file. Without it the Domains section says why and instances
	// use main-domain hosts only; the known list keeps being published.
	dom := domains.New(env("HUB_DOMAINS_API_URL", domains.DefaultAPIURL), env("HUB_DOMAINS_SECRET_FILE", domains.DefaultSecretFile))
	if err := dom.Available(); err != nil {
		log.Printf("domains disabled: %v", err)
	}
	h.SetDomainsAPI(dom)
	dirStore, err := openDirectoryStore(cfg.DataDir)
	if err != nil {
		log.Fatalf("refusing to start: %v", err)
	}
	dir := &directory.Service{
		LLDAP:   ll,
		KC:      kc,
		Invites: invites,
		Audit:   &directory.AuditLog{Path: filepath.Join(cfg.DataDir, "audit.jsonl")},
		Apps:    h.DirectoryApps,
		Store:   dirStore,
		// Same administrator groups core's invite API refuses (§9.4),
		// re-read on use so a map edit needs no restart.
		AdminGroups: func() map[string]bool {
			return directory.ProtectedGroups(os.Getenv("INVITE_PROTECTED_GROUPS"),
				env("HUB_GATE_MAP_FILE", filepath.Join(projectDir, "group-gate", "group-gate-map.conf")))
		},
	}
	wireDirectoryHooks(dir, h)
	// Instance operations are audited in the same log (contract §11.7);
	// instance groups go through the same guardrails (§11.4 step 5).
	h.SetAudit(dir.Audit)
	h.SetGroups(dir)
	// Per-person and per-group settings read LLDAP membership through the
	// directory; a group deleted there purges the setting rows naming it
	// in every instance (contract §13.4).
	h.SetPeople(dir)
	// Per-person claims: Hub-owned hidden LLDAP attributes (contract
	// §13.6); credentials are read on every call, so missing ones make
	// the claim units say "Users & Groups not configured".
	h.SetAttrStore(ll)
	dir.GroupDeleted = h.PurgeGroupSettings
	// Passwords the Hub sets are recorded (only those count, contract
	// §8.1); password onboarding follows the password method's switch.
	dir.PasswordSet = h.RecordPassword
	dir.PasswordMethodOn = h.PasswordMethodOn
	// Who has which sign-in method: Keycloak's passkeys, enroll's
	// YubiKey certificates (§8.1 "Inventory", §9.4).
	h.SetSignInSources(hub.SignInSources{Passkeys: kc.SignInCredentials, Certificates: invites.Certificates})
	dir.UserDeleted = h.PersonDeleted
	// The policy file's expiring list and user-attributes.json come from
	// the directory (contract §4, §4.1); shared fields become Keycloak
	// attr_<field> claims (§9.6). Keycloak failures are logged and retried,
	// never blocking the policy write.
	h.SetDirectory(hub.DirectoryStateOf(dir), func(ctx context.Context) error {
		shared, err := dir.SharedFields()
		if err != nil {
			return err // never remove mappers because directory.yaml is unreadable
		}
		fields := make([]keycloak.AttrField, 0, len(shared))
		for _, f := range shared {
			fields = append(fields, keycloak.AttrField{Name: f.Name, Multi: f.Multi})
		}
		return kc.EnsureAttributeMappers(ctx, fields)
	})
	// Fresh auth (contract §8): one verifier per listener (file-share
	// passwords and people confirmations on people.<d>, admin
	// confirmations on hub.<d>), and their one Keycloak client, ensured in
	// the directory sync loop.
	faHTTP := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for listener, redirect := range map[string]string{hub.ListenerPeople: fa.RedirectURI, hub.ListenerHub: fa.HubRedirectURI} {
		h.SetFreshAuth(listener, freshauth.New(freshauth.Config{
			Issuer: fa.Issuer, TokenURL: fa.TokenURL, JWKSURL: fa.JWKSURL,
			AuthorizeURL: fa.AuthorizeURL, RedirectURI: redirect,
			// The token endpoint never redirects; a redirect is refused.
			HTTP: faHTTP,
			// pc_fresh must be a fresh method switched on now (§8.1).
			Accepted: h.FreshAuthAccepted,
		}))
	}
	// Per-instance AI support (contract §8): the mcp:* scopes.
	h.SetAIKeycloak(kc)
	h.SetFreshAuthClient(func(ctx context.Context) error {
		return kc.EnsureFreshAuthClient(ctx, []string{fa.RedirectURI, fa.HubRedirectURI}, []string{fa.WebOrigin, fa.HubWebOrigin})
	})
	h.Init()

	srv := &httpapi.Server{
		Hub:        h,
		Directory:  dir,
		Audit:      dir.Audit,
		PortalName: os.Getenv("PORTAL_DISPLAY_NAME"),
		Secret:     secret,
		MCPSecret:  mcp.secret,
		Web:        web.FS,
		Docs:       web.Docs,
		// The Portcullis MCP redacts every result with these too (G40).
		RedactFiles:    []string{invites.SecretFile, dom.SecretFile, filepath.Join(ll.CredentialsDir, "password")},
		RedactLiterals: []string{os.Getenv("KEYCLOAK_ADMIN_PASSWORD")},
	}
	handler, err := srv.Handler()
	if err != nil {
		log.Fatalf("ui: %v", err)
	}
	// people.<domain> (contract §5.1): the directory UI and API only, for
	// every signed-in user; same proxy secret and CSRF guard.
	peopleHandler, err := srv.PeopleHandler()
	if err != nil {
		log.Fatalf("people ui: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go h.RunReconciler(ctx)
	go h.RunDirectorySync(ctx)
	go h.RunSettingsDelivery(ctx)
	go h.RunDomainSync(ctx, 30*time.Second)
	// The doctor's disk checks: daily (and on demand, after every folder
	// apply); cached in <data>/doctor/scans.json.
	go h.RunDoctorScans(ctx, 24*time.Hour)
	// Keycloak drops its copy of a user deleted straight in LLDAP only when
	// the user is looked up (removeInvalidUsersEnabled; its periodic LDAP
	// sync never removes users): list them all periodically. Keycloak
	// decides per user against LDAP; the Hub deletes nothing. Guarded: an
	// LLDAP that looks wrong (unreachable, admin or service account
	// missing, user count dropped) pauses it (hub/usersweep.go). An
	// unreachable skip retries every minute until success or pause; a
	// success or pause goes back to the normal 15-min interval.
	h.SetUserSweep(ll, kc)
	go runUserSweep(ctx, time.Minute, userRevalidateInterval, h)
	// SIGHUP syncs the template sources (core's `./portcullis upgrade`
	// sends it and reads the outcome from <data>/source-sync.json).
	go runOnSignal(ctx, hup, func() {
		st := h.SyncSourcesAs(hub.SyncSignal)
		log.Printf("sources: sync on SIGHUP finished (ok=%t)", st.OK)
	})
	// File-sharing holder checks (revoke on leave), on each trigger.
	go h.RunCredentialChecks(ctx)
	if dir.Store != nil {
		// Rule groups, exceptions and expiries -> LLDAP membership: every
		// minute (expiries) and after each directory mutation. Started
		// whatever LLDAP looks like at boot (F27): a run while it is
		// unavailable does nothing but still drives the holder check.
		go dir.RunEvaluator(ctx, time.Minute)
	}

	addr := env("HUB_LISTEN_ADDR", ":8888")
	peopleAddr := env("HUB_PEOPLE_ADDR", ":8889")
	servers := []*http.Server{newHTTPServer(addr, handler), newHTTPServer(peopleAddr, peopleHandler)}
	// The MCP listener (mcp-gate only, contract §15.7): only with its
	// secret. It listens on every Hub network; the secret protects it
	// and no Traefik router targets it (G36).
	if mcp.on {
		mcpHandler, err := srv.MCPHandler()
		if err != nil {
			log.Fatalf("mcp listener: %v", err)
		}
		servers = append(servers, newHTTPServer(mcp.addr, mcpHandler))
		log.Printf("MCP listener on %s (mcp-gate only)", mcp.addr)
	} else {
		log.Printf("MCP listener not started: %s is missing — AI support is off", mcp.file)
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		for _, s := range servers {
			s.Shutdown(shutdown)
		}
	}()
	log.Printf("Hub listening on %s, people on %s (domain: %s, docker: %s)", addr, peopleAddr, cfg.Domain, dockerHost)
	errc := make(chan error, len(servers))
	for _, s := range servers {
		go func() { errc <- s.ListenAndServe() }()
	}
	for range servers {
		if err := <-errc; err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}
	// Background backups / restores / deletes get a bounded time to finish
	// (core's stop_grace_period for the hub is longer); one still running
	// is marked interrupted at the next start.
	if !h.WaitTimeout(shutdownWait) {
		log.Printf("shutdown: background instance operations still running after %s — they are marked interrupted at the next start", shutdownWait)
	}
}

// mcpListener is the MCP listener's configuration (contract §15.7).
type mcpListener struct {
	addr, file, secret string
	on                 bool
}

// mcpListenerFromEnv reads HUB_MCP_ADDR (default :8890) and
// HUB_MCP_GATE_SECRET_FILE (default /run/portcullis/mcp-gate/hub-secret,
// core's mount): a missing file = off; a short or unreadable one is an
// error (the Hub refuses to start).
func mcpListenerFromEnv(getenv func(string) string) (mcpListener, error) {
	l := mcpListener{addr: getenv("HUB_MCP_ADDR"), file: getenv("HUB_MCP_GATE_SECRET_FILE")}
	if l.addr == "" {
		l.addr = ":8890"
	}
	if l.file == "" {
		l.file = "/run/portcullis/mcp-gate/hub-secret"
	}
	var err error
	l.secret, l.on, err = httpapi.LoadMCPSecret(l.file)
	return l, err
}

// userRevalidateInterval: how often Keycloak's users are listed (each
// one validated against LDAP).
const userRevalidateInterval = 15 * time.Minute

// runEvery runs fn after first, then every interval, until ctx ends.
func runEvery(ctx context.Context, first, interval time.Duration, fn func()) {
	t := time.NewTimer(first)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			fn()
			t.Reset(interval)
		}
	}
}

// runUserSweep runs the guarded sweep with adaptive retry: after an
// unreachable skip, it retries every hub.sweepRetry (1 minute) until a run
// completes or pauses, then goes back to the normal interval.
func runUserSweep(ctx context.Context, first, normalInterval time.Duration, h *hub.Hub) {
	t := time.NewTimer(first)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			rctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			h.RunUserSweep(rctx)
			cancel()
			st := h.UserSweep()
			// An unreachable skip retries soon; a success or pause goes
			// back to the normal interval.
			next := normalInterval
			if st.Skipped != "" {
				next = hub.SweepRetryInterval()
			}
			t.Reset(next)
		}
	}
}

// runOnSignal runs fn (one at a time) for each signal on ch until ctx
// ends.
func runOnSignal(ctx context.Context, ch <-chan os.Signal, fn func()) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-ch:
			fn()
		}
	}
}

// shutdownWait bounds the wait for background operations on shutdown.
const shutdownWait = 50 * time.Second

// newHTTPServer: both listeners use the same timeouts.
func newHTTPServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
}

// directoryHub is what the directory's change hooks drive.
type directoryHub interface {
	TriggerDirectorySync()
	TriggerCredentialCheck()
	MarkInventoryStale()
}

// wireDirectoryHooks sets dir's OnChange and OnEvaluated (both
// non-blocking). Expiries, user attributes and Keycloak mappers follow
// every directory change (coalesced in the Hub's background sync); so
// does the file-sharing holder check, at once (contract §13.16: Hub-made
// removals revoke with no debounce). The holder check also follows every
// evaluator run: its 60 s tick catches edits made straight in LLDAP
// (F27).
func wireDirectoryHooks(dir *directory.Service, h directoryHub) {
	dir.OnChange = func() {
		// Who has which sign-in method may have changed (a passkey
		// removed, an account created or deleted): the next guarded save
		// reads it again.
		h.MarkInventoryStale()
		h.TriggerDirectorySync()
		h.TriggerCredentialCheck()
	}
	dir.OnEvaluated = h.TriggerCredentialCheck
}
