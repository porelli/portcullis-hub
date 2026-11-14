// Package hub is the Hub's application core: template catalog, per-app
// lifecycle (enable/disable/restart) with per-app locking, env/override
// generation, template sources, the group-gate policy file and the
// state-vs-Docker reconcile loop. HTTP lives in internal/httpapi.
package hub

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net/http"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/portcullis/hub/internal/compose"
	"github.com/portcullis/hub/internal/confirm"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/idmap"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// ProjectPrefix prefixes every app's compose project name.
const ProjectPrefix = "portcullis-"

const (
	execTimeout = 15 * time.Minute
	gitTimeout  = 5 * time.Minute
)

// Config is the Hub's static configuration.
type Config struct {
	ProjectDir     string // core checkout as seen by the Hub (container path)
	ProjectHostDir string // same checkout as seen by the Docker daemon (host path)
	DataDir        string // writable state: state.yaml, env/, overrides/, repos/, policy file
	Domain         string
	// DefaultTemplatesURL is cloned as source "portcullis" when no source
	// is configured.
	DefaultTemplatesURL string
	// ReconcileInterval is the periodic drift check (default 60s).
	ReconcileInterval time.Duration
	// SyncSourcesAtStart: Init fast-forwards the git sources before the
	// first policy write (HUB_SYNC_SOURCES_AT_START, default on), so an
	// upgraded Hub never judges a stale template checkout.
	SyncSourcesAtStart bool
	// OverrideBindRoots is HUB_OVERRIDE_BIND_ROOTS: host directories custom
	// overrides may bind-mount from ("" = /srv:/mnt:/media).
	OverrideBindRoots string
	// AppFilesDir is where the Hub writes settings data files (contract
	// §13.7; "" = <ProjectDir>/appfiles, core's ./appfiles mount;
	// HUB_APPFILES_DIR overrides it). AppFilesHostDir is the same
	// directory as the Docker daemon sees it, for the override's bind
	// mounts ("" = <ProjectHostDir>/appfiles; the two are set together
	// or not at all: New refuses one without the other).
	AppFilesDir     string
	AppFilesHostDir string
	// FixerImage replaces the shared-folder fixer's image (contract §6): the
	// Hub's own image ID otherwise. Development only (main honours
	// HUB_FIXER_IMAGE only with HUB_DEV=1); must be pinned by @sha256.
	FixerImage string
	// SecretsDir is HUB_SECRETS_DIR, the hub_secrets volume as the Hub sees
	// it (contract §6, §13.16; "" = none: per-person passwords are
	// unavailable). SecretsVolume is its Docker name (HUB_SECRETS_VOLUME,
	// "" = DefaultSecretsVolume), mounted into apps by subpath.
	SecretsDir    string
	SecretsVolume string
	// MCPGateRecipientFile is HUB_MCP_GATE_RECIPIENT_FILE, the gate's age
	// recipient (contract §15.4; "" or unreadable = no gate: Settings → AI
	// shows gate_present false).
	MCPGateRecipientFile string
	// MCPListener: the MCP listener (HUB_MCP_ADDR, contract §15.7) runs —
	// main read a usable HUB_MCP_GATE_SECRET_FILE. false = the gate can't
	// reach the Hub (no mint, no Portcullis MCP), so AI support is off:
	// mcp-gate.json says enabled: false.
	MCPListener bool
	// MCPGateDataDir is HUB_MCP_GATE_DATA_DIR (core mounts mcp_gate_data
	// read-only at /mcp-gate-data): the gate's access.jsonl (§15.8) is
	// read there ("" = no access log: MyAI / AccessLog answer 503).
	MCPGateDataDir string
	// GroupGateDataDir is HUB_GROUP_GATE_DATA_DIR (core mounts
	// group_gate_data read-write at /group-gate-data): group-gate's opened
	// log is <dir>/opened, read for the sign-in history and pruned to
	// history_days (contract §8.2; "" = no opened log: that source is
	// unknown).
	GroupGateDataDir string
	// FIDOMDSURL is HUB_FIDO_MDS_URL, the FIDO Alliance MDS BLOB (contract
	// §8.1; "" = no fetching: no authenticators, passkeys register as
	// synced). Cached at <DataDir>/signin/mds.jwt.
	FIDOMDSURL string
	// ExtraAuthenticators is HUB_SIGNIN_EXTRA_AUTHENTICATORS (development
	// only: main honours it only with HUB_DEV=1), a JSON file of extra
	// trust-list entries merged over the FIDO list on every publish
	// (signin_mds.go).
	ExtraAuthenticators string
	// Dev is HUB_DEV=1: the extra authenticators are used only with it
	// (defence in depth: main refuses the file without it).
	Dev bool
	// ClientCertTTL is HUB_CLIENT_CERT_TTL (core's CLIENT_CERT_TTL, the
	// browser-cert role's max_ttl): its whole days are browser_cert_days'
	// ceiling (contract §8.1 "Limits"). main refuses to start under one
	// day; 0 here (tests) is a ceiling of 0: no lifetime is allowed.
	ClientCertTTL time.Duration
	// CertExpiryWarnDays is HUB_CERT_EXPIRY_WARN_DAYS read with core's
	// grammar (ParseCertExpiryWarnDays: ^[0-9]+$, else 7): a certificate
	// with fewer days left is "expiring" (contract §5.1). main always
	// sets it; 0 means nothing is ever expiring.
	CertExpiryWarnDays int
	// AccountURL is Keycloak's account console signing-in page
	// (https://<Keycloak's public host>/realms/portcullis/account/account-security/signing-in,
	// main: from HUB_KEYCLOAK_PUBLIC_URL), where people add passkeys and
	// security keys: the Sign-in page's "+ Add" ("" = no link).
	AccountURL string
	// ImpersonationMaxMinutes is HUB_IMPERSONATION_MAX_MINUTES (contract
	// §8.1 "Impersonation": 1–30, main refuses anything else; 0 here, in
	// tests, is the default 30).
	ImpersonationMaxMinutes int
	// Runtime is HUB_CONTAINER_RUNTIME (contract §6: docker or podman;
	// main refuses anything else) and Guard the engine guard verifying it
	// (main sets both). A nil Guard (unit tests) is never verified:
	// RuntimeView says verified false and the doctor gets no engine
	// inputs. Gates compare Runtime == docker.RuntimePodman only.
	Runtime docker.Runtime
	Guard   *docker.Guard
	// VPNStatusFile is HUB_VPN_STATUS_FILE, wg's status.json (contract
	// §16; main's default /wg-data/status.json; "" = wg is never up).
	VPNStatusFile string
	// VPNDocDir is HUB_VPN_DOC_DIR, the vpn_doc volume vpn.json is
	// written to (contract §4, §16; main's default /vpn-doc; "" = no
	// vpn.json: unit tests). VPNDocGID is HUB_VPN_DOC_GID, the file's
	// group (shared only with wg and group-gate).
	VPNDocDir string
	VPNDocGID int
	// VPNNet overrides portcullis-vpn's subnet (tests; zero = the core
	// env's PORTCULLIS_VPN_NET, default 172.31.254.0/26).
	VPNNet netip.Prefix
}

// Engine is the part of the Docker Engine API the Hub uses.
type Engine interface {
	ListContainers(ctx context.Context, f docker.Filters) ([]docker.Container, error)
	Logs(ctx context.Context, id string, tail int, timestamps bool) ([]byte, error)
	Exec(ctx context.Context, id string, cmd []string, timeout time.Duration) (*docker.ExecResult, error)
	Events(ctx context.Context, f docker.Filters, fn func(docker.Event)) error
	// Volumes and volume I/O (instance backups, guarded delete, the
	// volume collision check; docker/volumes.go).
	ListVolumes(ctx context.Context, f docker.Filters) ([]docker.Volume, error)
	InspectVolume(ctx context.Context, name string) (docker.Volume, error)
	CreateVolume(ctx context.Context, v docker.Volume) error
	RemoveVolume(ctx context.Context, name string) error
	EnsureImage(ctx context.Context, ref string) error
	// PullWithProgress downloads ref unless present (docker/pull.go):
	// startUp's images step, before compose create.
	PullWithProgress(ctx context.Context, ref string, onBytes func(done, total int64, sized bool)) error
	CreateHelper(ctx context.Context, s docker.HelperSpec) (string, error)
	RemoveContainer(ctx context.Context, id string) error
	CopyFromContainer(ctx context.Context, id, path string) (io.ReadCloser, error)
	CopyToContainer(ctx context.Context, id, path string, content io.Reader) error
	// ContainerKill signals a container (a settings reload, §13.8);
	// ContainerState is its run state and health after the grace period.
	ContainerKill(ctx context.Context, id, signal string) error
	ContainerState(ctx context.Context, id string) (docker.State, error)
	// ExecStdin runs a settings hook (§13.8): argv, stdin written then
	// closed, no TTY; ExecRunning: a timed-out exec still runs (Docker
	// can't kill it: the next hook run waits for it).
	ExecStdin(ctx context.Context, id string, in docker.ExecInput) (*docker.ExecResult, error)
	// ExecStdinSplit runs an AI hook (§15.5, G6): stdout and stderr apart.
	ExecStdinSplit(ctx context.Context, id string, in docker.ExecInput) (*docker.ExecSplitResult, error)
	ExecRunning(ctx context.Context, execID string) (bool, error)
	// RunHelper runs the shared-folder fixer, a STARTED helper (contract
	// §6, fixer.go); InspectContainer finds the Hub's own image;
	// SecurityOptions is the daemon's Info (userns / rootless refusal).
	RunHelper(ctx context.Context, s docker.RunSpec, out func(tar io.Reader) error) (*docker.RunResult, error)
	InspectContainer(ctx context.Context, id string) (docker.ContainerInfo, error)
	SecurityOptions(ctx context.Context) ([]string, error)
	// DockerRootDir is the daemon's data root (no shared folder at,
	// above or under it).
	DockerRootDir(ctx context.Context) (string, error)
	// APIVersion is the daemon's highest Engine API version (volume
	// subpath mounts need 1.45, contract §6).
	APIVersion(ctx context.Context) (string, error)
	// ListNetworks lists the engine's networks with their subnets (the
	// VPN wiring's overlap guard, contract §3.3).
	ListNetworks(ctx context.Context) ([]docker.Network, error)
}

// IdP manages the OIDC clients templates declare.
type IdP interface {
	// RegisterClient creates or reconciles a client; created: this call
	// created it (an enable's Stop deletes only those).
	RegisterClient(ctx context.Context, s keycloak.ClientSpec) (created bool, err error)
	// UpdateClientHosts moves an instance client's redirect URIs and web
	// origins to new hostnames (keycloak.Client.UpdateClientHosts).
	UpdateClientHosts(ctx context.Context, s keycloak.ClientSpec, oldURIs []string, hostMap map[string]string) error
	// UpdateForwardAuthCallbacks adds/removes extra-domain callback URIs
	// on portcullis-forward-auth (contract §5).
	UpdateForwardAuthCallbacks(ctx context.Context, add, remove []string) error
	// EnsureClientAccess / RemoveClientAccess manage an instance client's
	// access role, group mapping and access flow (contract §8).
	EnsureClientAccess(ctx context.Context, s keycloak.AccessSpec) error
	RemoveClientAccess(ctx context.Context, clientID, owner string, allowedHosts []string) error
	// DeleteClient deletes a client tagged with owner (guarded delete);
	// missing = nil, anything else of someone else's = *ConflictError.
	DeleteClient(ctx context.Context, clientID, owner string) error
	// EnsureSettingClaims / RemoveSettingClaims manage an instance
	// client's per-person setting claims (contract §13.6: LDAP mappers
	// and that client's protocol mappers portcullis-setting-<attr>; only
	// a client tagged with owner, else *ConflictError).
	EnsureSettingClaims(ctx context.Context, clientID, owner string, claims []keycloak.SettingClaim) error
	RemoveSettingClaims(ctx context.Context, clientID, owner string, attrs []string) error
}

// Groups manages app instances' LLDAP groups through the Users & Groups
// guardrails (directory.Service: CreateGroup / DeleteGroup as actor,
// audited there). Warnings are reported, not errors.
//
// actor must be an administrator the Users & Groups side resolves
// (directory CallerFor + lldap_admin): ResolveActor checks that, and the
// Hub calls it before any destructive step of an operation that will
// need the groups (delete, restore into a new id), so a bad actor fails
// before anything changes.
type Groups interface {
	ResolveActor(ctx context.Context, actor directory.Actor) error
	CreateInstanceGroup(ctx context.Context, actor directory.Actor, name string) (created bool, warnings []string, err error)
	// MissingInstanceGroups returns the names that are no LLDAP group
	// (read-only; an error: unknown, nothing is created).
	MissingInstanceGroups(ctx context.Context, names []string) ([]string, error)
	DeleteInstanceGroup(ctx context.Context, actor directory.Actor, name string) ([]string, error)
	// CheckBindGroups checks the groups an instance is bound to (contract
	// §11.9 groups mode "existing"; "" = none of that kind): each must
	// exist (400 "unknown group <name>"), the users group may not be a
	// built-in, administrator or permission group (400); Users & Groups
	// down is 503. It answers the names as LLDAP has them.
	CheckBindGroups(ctx context.Context, users, admins string) (string, string, error)
}

// People is the directory as per-person and per-group settings read it
// (directory.Service): LLDAP membership with group ids, and whether a
// group may hold a privileged value. Network calls: never call them
// holding mu (lock order: directory s.mu → Hub.mu).
type People interface {
	Membership(ctx context.Context, now time.Time) (*directory.Membership, error)
	PrivilegeProblem(ctx context.Context, group string) (string, error)
}

// SetPeople wires the directory for per-person / per-group settings (nil:
// such saves are 503, populations unknown).
func (h *Hub) SetPeople(p People) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.people = p
}

// FolderSource resolves a shared folder (project 2) to its host
// directory. It is called under the Hub lock: it must answer from
// memory, never over the network.
type FolderSource interface {
	FolderHostPath(id, subpath string) (string, error)
}

// SetFolderSource sets where shared-folder path values resolve.
func (h *Hub) SetFolderSource(f FolderSource) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.folders = f
}

// Kinds is the Hub's settings type registry.
func (h *Hub) Kinds() *settings.Registry { return h.kinds }

// Hub is the application core. All exported methods are safe for
// concurrent use.
type Hub struct {
	cfg Config
	// kinds is the settings type registry (immutable after New).
	kinds *settings.Registry
	// folders resolves shared-folder path values (project 2; SetFolderSource;
	// nil = not available: folder:… values are refused). Guarded by mu.
	folders FolderSource
	// folderLocks: per shared folder id, the *sync.Mutex its operations
	// try-lock (folders.go folderLock).
	folderLocks sync.Map
	// folderApplying: instance → the shared folder whose assignment or
	// undo is running on it (folderassign.go; pendingLocked answers 409,
	// ruling 6). Guarded by mu.
	folderApplying map[string]string
	// startedAt: when each instance last started cleanly (startUp, under
	// mu): runtime gids read before it are not judged (H11 M6).
	startedAt map[string]time.Time
	// testHookSave, if set, runs in SaveSettings between its checks
	// outside mu and the commit under mu (tests: a race with an
	// assignment).
	testHookSave func()
	// testHookManageDefined, if set, runs in manage_as_folder's apply
	// right after the definition is created, before the assignment is
	// validated (doctorfix.go).
	testHookManageDefined func()
	compose               compose.Runner
	engine                Engine
	idp                   IdP
	attrs                 AttrStore // LLDAP user attributes (setting claims); nil: none
	// fixerImage caches selfImage (fixer.go; guarded by fixerMu, never
	// mu); mountinfo reads /proc/self/mountinfo (test-settable).
	fixerMu    sync.Mutex
	fixerImage string
	mountinfo  func() ([]byte, error)
	// readIDMaps reads the Hub's own uid_map / gid_map (runtime_engine.go;
	// nil = /proc/self, test-settable).
	readIDMaps func() (uid, gid idmap.Map, err error)
	// selinuxMu guards the engine's cached SELinux flag
	// (doctor_engine.go engineSELinux; a leaf lock).
	selinuxMu    sync.Mutex
	selinuxKnown bool
	selinuxOn    bool
	// The doctor's disk scans (doctorscan.go): scanMu = one scan at a
	// time (try-lock, 409); scanCacheMu (a leaf lock, never held with a
	// fixer or docker call) guards scanData, the <data>/doctor/scans.json
	// cache (nil = not loaded yet) and scanCtx, the scheduler's context
	// (on-demand scans stop with it); scanStartDelay: the first scheduled
	// scan's delay (0 = defaultScanStartDelay; tests).
	scanMu         sync.Mutex
	scanCacheMu    sync.Mutex
	scanData       *scanFile
	scanCtx        context.Context
	scanStartDelay time.Duration
	// gidExecs: per container, gid-check execs that timed out (Docker
	// can't kill them; under scanCacheMu, M8).
	gidExecs map[string][]string
	// The main domain's A / AAAA lookup (localnet.go): lookupIP
	// (test-settable), its cache under dnsMu (never mu).
	lookupIP lookupIPFunc
	dnsMu    sync.Mutex
	dnsCache dnsCache
	// domains lists the main and enrolled domains (hosts.go); audit
	// receives instance operations (SetAudit). Both guarded by mu.
	domains DomainSource
	audit   Auditor
	// groups creates / deletes instance groups (SetGroups; nil = not
	// available: a warning). Guarded by mu.
	groups Groups
	// people reads LLDAP membership for per-person settings (SetPeople;
	// nil = not available). Guarded by mu.
	people People
	// freshAuth verifies fresh-auth proofs, per listener (freshauth.go;
	// none: refused).
	freshAuth map[string]FreshAuth
	// freshAuthReady: the last ensure of the fresh-auth Keycloak client
	// succeeded (runAttrSync); false at start and after any failure —
	// e.g. an untagged client of that id (*keycloak.ConflictError) — so
	// every proof is refused until the client is known to be right.
	freshAuthReady atomic.Bool
	// The settings delivery engine (deliver.go). deliveryMu guards queued
	// (debounced and re-queued runs per instance) and deliveryStatus (the
	// last outcome per instance and unit, mirrored in delivered.json).
	// deliverLocks: per instance, the *sync.Mutex every run holds.
	deliveryMu     sync.Mutex
	queued         map[string]*queuedDelivery
	deliveryStatus map[string]map[string]UnitResult
	lastTrigger    map[string]Trigger
	// lastMembers: user → groups (expired left out) at the last
	// TriggerMembershipDelivery, to tell a removal (under deliveryMu).
	lastMembers  map[string]map[string]bool
	deliverLocks sync.Map
	// entryLimit: refused people-entry saves per caller (entries.go);
	// entryNow its clock (nil: time.Now; tests set it).
	entryLimit entryLimiter
	entryNow   func() time.Time
	// hookExecs: per instance, a timed-out hook exec that may still run
	// (deliver_hooks.go; under deliveryMu).
	hookExecs map[string]timedOutExec
	// hookStuck: per instance, re-queues since the last real trigger
	// while a timed-out exec still runs (under deliveryMu).
	hookStuck map[string]int
	// The engine's clock (test-settable): afterFunc arms a timer (returns
	// its stop), sleep waits out the reload grace period.
	afterFunc func(d time.Duration, f func()) (stop func() bool)
	sleep     func(ctx context.Context, d time.Duration) error
	// deliverHook, if set, is called at engine stages (tests).
	deliverHook func(id, stage string)
	// domainsAPI is core's domains service (domains.go; nil = not
	// configured); domainsReachable: its last call succeeded. Both guarded
	// by mu. domainOpMu serialises enroll / token / delete (held across
	// the service calls, never together with mu).
	domainsAPI       DomainsAPI
	domainsReachable bool
	// domainsDeleting: names a DeleteDomain is removing (not assignable
	// meanwhile); domainsGen changes with every domain operation's commit,
	// so a RefreshDomains that started before it drops its stale list.
	domainsDeleting map[string]bool
	domainsGen      uint64
	domainOpMu      sync.Mutex

	// mu guards st and templates. Never hold it across docker/network calls.
	mu        sync.RWMutex
	st        *state.AppState
	templates []templates.Template // the catalog, by template id
	// catalogGen counts catalog replacements (Discover): a create's setup
	// values checked against one catalog commit only against it.
	catalogGen uint64
	// instances are the instance views (instances.go): the default
	// instance of every catalog template plus state's instances.
	instances []templates.Template
	// brokenInstances: instance id → why it has no view (template missing
	// or its hostnames no longer fit); listed with state "error".
	brokenInstances map[string]string
	// hostHeaders: per instance, the header deliveries last delivered
	// (deliver_headers.go): host → header suffix → user → value. Not in
	// delivered.json: Init reads it back from user-attributes.json's
	// hosts section (seedHostHeaders); disabled / view-less instances'
	// records are dropped (rebuildLocked).
	hostHeaders map[string]map[string]map[string]map[string]string
	// allTemplates is every template discovered in any source (duplicates
	// and skipped ones included): their default names are reserved
	// (§11.1). templateIDs are their ids.
	allTemplates []templates.Template
	templateIDs  map[string]bool

	// appOps serialises lifecycle operations per app so the slow parts can
	// run without holding mu.
	appOps    sync.Map
	sourceOps sync.Map
	// sourceSyncMu serialises source syncs; sourceSyncSt (guarded by
	// sourceSyncStMu) is the last one's status (sources.go).
	sourceSyncMu   sync.Mutex
	sourceSyncStMu sync.Mutex
	sourceSyncSt   *SourceSyncStatus
	// sweep: the guarded Keycloak stale-record sweep (usersweep.go).
	sweep *userSweep
	// syncMu: per template id, a *sync.Mutex around its support-file sync
	// (shared by all its instances).
	syncMu sync.Map
	// syncHashes: template dir → tree hash last published there
	// (<data>/template-sync.json); guarded by syncHashMu.
	syncHashMu sync.Mutex
	syncHashes map[string]string
	// lockPoll is how often a queued restart retries the app lock;
	// restartWait how long it tries before giving up (a failed restart
	// op record; the restart stays owed).
	lockPoll    time.Duration
	restartWait time.Duration
	// owed: per instance, the strongest effect (reload, restart) a
	// committed change still owes, mirrored in delivered.json "owed"
	// (Init re-queues it); owedSeq counts its updates. Under owedMu,
	// which also serialises every delivered.json write.
	owedMu sync.Mutex
	// envProblems: per instance, the option env values written empty
	// (optionEnvLocked; under envProblemsMu, a leaf lock).
	envProblemsMu sync.Mutex
	envProblems   map[string][]string
	owed          map[string]string
	owedSeq       map[string]int64

	// envDrops: per instance, the stored env overrides the last .env
	// write skipped (envOverrideBlockLocked; under envProblemsMu).
	envDrops map[string][]string

	// bg tracks background lifecycle work (queued restarts) so callers
	// can wait for it.
	bg sync.WaitGroup

	policyWriteMu sync.Mutex
	// mds: the FIDO list signin-keycloak.json's authenticators come from
	// (signin_mds.go; its own leaf lock).
	mds mdsState
	// signInMu serialises Settings → Sign-in writers (signin.go), from
	// their plan to their commit; taken before mu.
	signInMu sync.Mutex
	// signInInv: who has which sign-in method (signin_people.go; its own
	// leaf locks, never held across mu).
	signInInv inventoryCache
	// certActions issues, renews and revokes certificates through enroll
	// (SetCertActions; nil: those actions are 503). Guarded by mu.
	certActions CertActions
	// ownPasswords sets and removes a person's own password
	// (SetOwnPasswords; nil: 503). Guarded by mu.
	ownPasswords OwnPasswords
	// signInHelp decides who may act on another person's sign-in
	// (SetSignInHelp; nil: those routes are 503). Guarded by mu.
	signInHelp SignInHelp
	// certCreate: per user, the *sync.Mutex a browser certificate create
	// holds (one create at a time per person).
	certCreate sync.Map
	// certNow is the certificate status clock (nil: time.Now; tests).
	certNow func() time.Time
	// imp: the administrators' impersonations (impersonation.go).
	imp impState
	// signInBetweenPlans (tests only, nil in production) runs in
	// changeSignIn between its two plans, outside mu: a writer that comes
	// in between.
	signInBetweenPlans func()

	driftMu sync.Mutex
	drift   DriftReport
	// runtimeHosts: full hostnames (any domain) routed by each app
	// project's containers (from their Traefik labels), as last seen by
	// Reconcile.
	runtimeHosts map[string][]string
	driftKey     map[string]string
	kick         chan struct{}
	bindRoots    []string // validated OverrideBindRoots

	// ops: each app's last lifecycle operation (mirrors <data>/ops).
	opsMu sync.Mutex
	ops   map[string]OpRecord
	// hostsOps: each instance's last hostname change (OpHosts), kept
	// apart from ops (mirrors <data>/ops/<id>.hosts.json).
	hostsOps map[string]OpRecord
	// startHookFailed: a start hook failed during the lifecycle operation
	// holding the instance's lock (composeUp): that operation's success
	// keeps the hook's failure record (cleared when the lock is released).
	startHookFailed map[string]bool
	// heldHook: a hook's failure record held while another operation's
	// record was running (finishOpGuarded), written by finishAsync once
	// that operation ended ok; under opsMu. Each is that operation's
	// (opID): another operation's end never drops or writes it.
	heldHook map[string]heldHookRec
	// opRuns: the stop registry (progress.go) — each running background
	// operation by its record key, with its reporter and cancel; under
	// opRunsMu, a leaf lock. progressNow / progressAfter: the reporter's
	// clock and its throttle timer (nil: time.Now / time.AfterFunc;
	// test-settable — apart from the delivery engine's afterFunc, whose
	// tests count its timers).
	opRunsMu      sync.Mutex
	opRuns        map[string]*opRun
	progressNow   func() time.Time
	progressAfter func(d time.Duration, f func()) (stop func() bool)
	// testHookStepStart, if set, runs at the end of every Progress.Start
	// (op, step key), without any lock held (tests block a step there).
	testHookStepStart func(op, key string)
	// testHookCommit, if set, runs right before ("before") and right
	// after ("after") an enable's commit gate, and ("enable_failed")
	// before a failed enable closes its gate, no lock held.
	testHookCommit func(id, stage string)
	// testHookResume, if set, runs in resumeStop before it takes the
	// instance's lock (tests interleave a second request there).
	testHookResume func(id string)
	// testHookResumeUnlocked, if set, runs in a resumed Stop's goroutine
	// after it released the lock and before it ends its record (tests
	// start another operation in that gap).
	testHookResumeUnlocked func(id string)

	// Directory publishing (SetDirectory). lastExpiring is the expiring
	// list last written (guarded by policyWriteMu; nil: not yet known).
	dirState DirectoryState
	attrSync func(ctx context.Context) error
	// freshAuthEnsure re-asserts the fresh-auth Keycloak client in the
	// directory sync loop (freshauth.go); under policyWriteMu like attrSync.
	freshAuthEnsure func(ctx context.Context) error
	// eventsEnsure re-asserts Keycloak's events config with history_days
	// (signin_limits.go: the sync loop and every limits change); under
	// policyWriteMu like attrSync.
	eventsEnsure func(ctx context.Context, days int) error
	// eventsMu serialises ensureEvents (never held with mu across the
	// Keycloak call; mu is taken inside it only to read history_days).
	eventsMu sync.Mutex
	// history is the sign-in history's wiring (signin_history.go).
	history      historyState
	lastExpiring []policy.Expiring
	dirKick      chan struct{}
	// invKick asks runInventorySync for a sign-in inventory refresh.
	invKick chan struct{}

	// Person-id pools (personids.go, contract §13.16): idRanges = pool →
	// its inclusive id range (templates.PersonIDPools; tests narrow it);
	// poolsAdvanced: AdvancePools ran in this process (once only). Under
	// mu.
	idRanges      map[string][2]int
	poolsAdvanced bool
	// secretsErr: why SecretsDir can't hold credentials (checkSecretsDir
	// in New; nil = usable; immutable after New, F14).
	secretsErr error
	// secretsReconcileErr: the last secrets reconcile failed (under mu;
	// nil = it succeeded): person_secret starts and SecretsUsable refuse
	// (503) until a reconcile succeeds.
	secretsReconcileErr error
	// revokeLockWait: how long a revocation tries for an instance's
	// delivery lock (credentials.go; revokeLockWaitDefault, tests shorten
	// it). credentialCheck: the holder re-check a create asks for (F30;
	// New sets TriggerCredentialCheck; nil: none). Both set before use,
	// never changed.
	revokeLockWait time.Duration
	// lifecycleDeliverWait: how long a lifecycle down waits for the
	// instance's delivery lock (an in-flight revocation hook, H7).
	lifecycleDeliverWait time.Duration
	// testHookAwaitDelivery: called by each awaitDelivery (tests).
	testHookAwaitDelivery func(id string)
	credentialCheck       func()
	// credKick: TriggerCredentialCheck's coalesced request, served by
	// RunCredentialChecks (revoke.go). credCheckErr: the last check's
	// error text (logged once per distinct error; RunCredentialChecks'
	// goroutine only).
	credKick     chan struct{}
	credCheckErr string
	// testHookHolderJudged, if set, runs in CheckCredentialHolders
	// between the judgement and the revocations (tests: a change racing
	// the check).
	testHookHolderJudged func()
	// AI gate files (ai_gatefile.go, ai_credstore.go): aiHealth = the AI
	// client ids the last Keycloak ensure left in place (under mu; nil =
	// unknown: none listed); gateStale = the last gate write failed (the
	// directory sync loop retries); callerDigests = sha256 of each caller
	// secret last encrypted (under policyWriteMu); aiCreds the store.
	aiHealth      map[string]bool
	gateStale     atomic.Bool
	callerDigests map[string]string
	credsOnce     sync.Once
	aiCreds       *aiCredStore
	// confirmStore: the confirmations (confirm.go; in memory, created on
	// first use under confirmOnce).
	confirmOnce  sync.Once
	confirmStore *confirm.Store
	// mints: single flight per (resource, user) of MintCredential
	// (ai_credentials.go, G35).
	mints singleflight.Group
	// Per-instance AI support (ai_instance.go): aiKC the mcp:* scope calls
	// (under mu); aiLocks the per-instance AI locks (waiting); aiErrs each
	// companion's last error, redacted (under aiErrMu, memory only).
	aiKC    AIKeycloak
	aiLocks sync.Map
	// aiHeld: instances whose AI lock a lifecycle operation holds
	// (lifecycleAILock).
	aiHeld  sync.Map
	aiErrMu sync.Mutex
	aiErrs  map[string]string
	// testOverrideWriteErr, if set, fails override writes (tests: the
	// VPN fail-closed path).
	testOverrideWriteErr func(path string) error
	// vpnrt is the VPN providers' memory (vpn_providers.go; own mutex).
	vpnrt *vpnRuntime
	// aiReapply: per instance, the companions whose last change failed
	// after its state save (under aiErrMu); aiApplying: instances an
	// UpdateInstanceAI is applying (startUp leaves the owed hooks to it).
	aiReapply  map[string]map[string]bool
	aiApplying sync.Map
	// Revocation reconcile (ai_revoke.go, Task 13b): aiReconKick kicks
	// runAIReconcile, aiReconMu serialises passes; aiRevokeErrs the last
	// audited failure per revocation and aiPrunedErrs per Pruned companion
	// (both under aiErrMu, memory only).
	aiReconKick  chan struct{}
	aiReconMu    sync.Mutex
	aiRevokeErrs map[string]string
	aiPrunedErrs map[string]string
	// app_oauth reconcile memory (T27; the records themselves are all in
	// oauth-seen.json): aiOwedRevokeAll — per companion, the unverifiable
	// leavers whose revoke_all failed at the last pass (wording only: the
	// cause stays on disk); aiPendingPasses — per companion and person,
	// passes their Keycloak id lookup failed; aiSeenUnwritten — holders a
	// failed oauth-seen.json write left unrecorded (recorded unverifiable
	// by the next write) and that write's error.
	aiOwedRevokeAll  map[string][]string
	aiPendingPasses  map[string]map[string]int
	aiSeenUnwritten  map[string][]string
	aiSeenWriteError string
	// Keycloak AI clients (ai_clients.go): aiKCMu serialises every pass
	// over the AI clients and mcp:* scopes (the sync loop, a Settings → AI
	// save, applyAIScopes), each reading state after taking it — a leaf
	// lock, only mu (read) inside; aiMasterGen counts master switch
	// changes (under mu: UpdateInstanceAI's commit refuses a plan made
	// before one); aiClientErrs the last logged error per client (under
	// aiKCMu: logged once per distinct text).
	aiKCMu       sync.Mutex
	aiMasterGen  uint64
	aiClientErrs map[string]string
	// aiOwedDrops: mcp:* scopes whose delete failed (under aiKCMu;
	// memory): every client pass retries them while still unwanted.
	aiOwedDrops map[string]bool
	// testHookDeleteBackedUp, if set, runs in a delete right after its
	// backup, before the deleting state is committed (Task 23 fix round 1).
	testHookDeleteBackedUp func(id string)
	// testHookAIBeforeSave, if set, runs in UpdateInstanceAI right before
	// its state commit (tests: a racing policy save).
	testHookAIBeforeSave func()
	// testHookAIAfterSave, if set, runs right after that commit (tests:
	// the flags a crash there would leave).
	testHookAIAfterSave func()
	// testHookInit, if set, is called at Init's stages (tests: order).
	testHookInit func(stage string)
	// testHookApplyRestore, if set, runs at applyRestore's stages
	// ("volumes": after the volume fills); an error fails the restore.
	testHookApplyRestore func(stage string) error
}

// New loads state from cfg.DataDir and prepares the data directories. It
// fails on a corrupt state file rather than starting empty.
func New(cfg Config, runner compose.Runner, engine Engine, idp IdP) (*Hub, error) {
	if cfg.ProjectHostDir == "" {
		cfg.ProjectHostDir = cfg.ProjectDir
	}
	if cfg.ReconcileInterval <= 0 {
		cfg.ReconcileInterval = time.Minute
	}
	switch {
	case cfg.AppFilesDir == "" && cfg.AppFilesHostDir == "":
		cfg.AppFilesDir = filepath.Join(cfg.ProjectDir, "appfiles")
		cfg.AppFilesHostDir = filepath.Join(cfg.ProjectHostDir, "appfiles")
	case cfg.AppFilesDir == "" || cfg.AppFilesHostDir == "":
		// Fail closed: a guessed daemon path would bind-mount a wrong
		// (Docker-created, root-owned, empty) directory into apps.
		return nil, fmt.Errorf("HUB_APPFILES_DIR and HUB_APPFILES_HOST_DIR must be set together (the data file directory as the Hub and as the Docker daemon see it); unset both for <PROJECT_DIR>/appfiles")
	}
	for _, d := range []string{cfg.DataDir, filepath.Join(cfg.DataDir, "repos"), filepath.Join(cfg.DataDir, "env"), filepath.Join(cfg.DataDir, "overrides"), filepath.Join(cfg.DataDir, "ops")} {
		if err := os.MkdirAll(d, 0755); err != nil {
			return nil, err
		}
	}
	roots, err := ParseBindRoots(cfg.OverrideBindRoots, cfg.ProjectHostDir)
	if err != nil {
		return nil, err
	}
	// Fail closed: an unpinned, env-selected root-capable image (S1).
	if cfg.FixerImage != "" && (!strings.Contains(cfg.FixerImage, "@sha256:") || !docker.PinnedImage(cfg.FixerImage)) {
		return nil, fmt.Errorf("HUB_FIXER_IMAGE %q must be pinned by digest (name@sha256:<64 hex>)", cfg.FixerImage)
	}
	if cfg.SecretsVolume == "" {
		cfg.SecretsVolume = DefaultSecretsVolume
	}
	if !volumeNameRe.MatchString(cfg.SecretsVolume) {
		return nil, fmt.Errorf("HUB_SECRETS_VOLUME %q is not a volume name", cfg.SecretsVolume)
	}
	h := &Hub{
		vpnrt:                newVPNRuntime(),
		kinds:                settings.NewRegistry(),
		bindRoots:            roots,
		cfg:                  cfg,
		compose:              runner,
		engine:               engine,
		idp:                  idp,
		lockPoll:             2 * time.Second,
		restartWait:          20 * time.Minute,
		revokeLockWait:       revokeLockWaitDefault,
		lifecycleDeliverWait: lifecycleDeliverWaitDefault,
		kick:                 make(chan struct{}, 1),
		dirKick:              make(chan struct{}, 1),
		invKick:              make(chan struct{}, 1),
		aiReconKick:          make(chan struct{}, 1),
		credKick:             make(chan struct{}, 1),
		driftKey:             map[string]string{},
		afterFunc:            realAfterFunc,
		sleep:                realSleep,
		mountinfo:            func() ([]byte, error) { return os.ReadFile("/proc/self/mountinfo") },
		lookupIP:             defaultLookupIP,
		idRanges:             templates.PersonIDPools,
	}
	h.mds.fetcher = newMDSFetcher(cfg)
	// A create's holder re-check (F30) is the trigger RunCredentialChecks
	// serves.
	h.credentialCheck = h.TriggerCredentialCheck
	// The secrets volume (F14): unusable = fail closed, the Hub still
	// starts.
	if h.secretsErr = checkSecretsDir(cfg.SecretsDir); h.secretsErr != nil && cfg.SecretsDir != "" {
		log.Printf("ERROR: secrets: %v — per-person passwords are unavailable and apps with them won't start", h.secretsErr)
	}
	// The known list in state.yaml (empty = only the main domain).
	h.domains = knownDomains{h}
	st, err := state.Load(h.statePath())
	if err != nil {
		return nil, err
	}
	h.st = st
	// Shared folders resolve from state (folders.go; P8); a stored folder
	// this configuration refuses stops the start (P24).
	h.folders = hubFolders{h}
	if err := h.checkFoldersAtStart(); err != nil {
		return nil, err
	}
	h.loadOps()
	h.loadSyncHashes()
	h.loadVPNRendered()
	return h, nil
}

// Init removes backup / restore leftovers (SweepBackupLeftovers), clones
// the default source on first run, discovers templates, syncs the git
// sources (Config.SyncSourcesAtStart; fail-safe, sources.go), rolls back
// interrupted restores in the background (RecoverRestores) and seeds the
// group-gate policy file.
func (h *Hub) Init() {
	// The sign-in defaults (D1 / D11 / D12) of a state that lacks them,
	// before anything reads them.
	h.ensureSignIn()
	// Before anything can start a backup or restore.
	h.SweepBackupLeftovers()
	// The secrets epoch (§11.6) before anything can start or deliver: a
	// core restore voids every credential and advances the person-id
	// pools before any allocation (interrupted restores, folder applies
	// and owed restarts below all start instances).
	h.initStage("secrets")
	if h.cfg.SecretsDir != "" || len(h.st.Credentials) > 0 {
		if _, err := h.reconcileSecrets("start"); err != nil {
			log.Printf("secrets: start-up check: %v", err)
		}
	}
	h.autoLoadDefaultTemplates()
	h.Discover()
	// Fresh templates before the first policy write: the policy file the
	// previous run wrote keeps serving meanwhile. A failed pull keeps the
	// checkout as it is (sources.go).
	if h.cfg.SyncSourcesAtStart {
		st := h.syncSources(SyncStartup, StartupSyncTimeout)
		if !st.OK {
			log.Printf("sources: start-up sync incomplete — the previous template versions are kept (see above)")
		}
	}
	// After the final Discover: stored settings of options the templates
	// removed, retyped or rescoped are dropped (audited; P9).
	h.pruneSettings()
	// Companions the templates dropped or changed are switched off and
	// their credentials revoked (G33); the restart is owed (requeueOwed).
	h.pruneAI(false)
	// Interrupted same-instance restores are rolled back (background).
	h.RecoverRestores()
	// Interrupted shared-folder applies and undos: their stopped apps are
	// started again with what state.yaml holds (background; never a
	// fixer run, contract §14.3).
	h.RecoverFolderApplies()
	// The header deliveries group-gate serves now: what the first policy
	// write publishes again (P13).
	h.seedHostHeaders()
	// G74: only the files other containers read may be group-readable.
	h.checkDataDirModes()
	// The built-in VPN subnet as wg reports it, before anything renders
	// an allowlist (I7).
	h.wgStatus()
	if err := h.WritePolicy(); err != nil {
		log.Printf("auth-policy: initial group-gate policy write failed: %v", err)
	}
	// vpn.json: wired marketplace providers are stale until their first
	// run (contract §16).
	h.TriggerVPNPublish()
	// Reloads and restarts committed changes still owe (the previous run
	// stopped before applying them): queued again.
	h.initStage("requeue")
	// AI hooks a running instance still owes (a crash between a switch's
	// or the master toggle's commit and the up that runs them): the
	// containers kept running with the old env, so a restart is owed;
	// its start runs the owed revoke_all / on_change (final review I2).
	h.oweAIPendingRestarts()
	if h.engineVerifiedNow() {
		h.requeueOwed()
	} else {
		h.afterEngineVerified("settings: owed reloads and restarts", h.requeueOwed)
	}
	// VPN (I2): running labels the rendering narrowed (or that can't be
	// read) restart the instance.
	eng := h.engine
	vpnCheck := func() { h.vpnStartCheck(context.Background(), eng) }
	if h.engineVerifiedNow() {
		h.goBackground(vpnCheck)
	} else {
		h.afterEngineVerified("vpn: running labels against the rendering", vpnCheck)
	}
}

// oweAIPendingRestarts owes a restart to every enabled instance with a
// companion carrying RevokePending or OnChangePending.
func (h *Hub) oweAIPendingRestarts() {
	var ids []string
	h.mu.RLock()
	for _, id := range h.st.Enabled {
		for _, c := range h.st.AIInstances[id].Companions {
			if c.RevokePending || c.OnChangePending {
				ids = append(ids, id)
				break
			}
		}
	}
	h.mu.RUnlock()
	for _, id := range ids {
		log.Printf("ai: %s: AI hooks are still owed: restart queued", id)
		h.setOwed(id, settings.EffectRestart)
	}
}

// initStage calls testHookInit (tests).
func (h *Hub) initStage(stage string) {
	if h.testHookInit != nil {
		h.testHookInit(stage)
	}
}

// Wait blocks until queued background restarts and policy propagation
// have finished.
func (h *Hub) Wait() { h.bg.Wait() }

// WaitTimeout is Wait bounded by d (shutdown: background backups,
// restores and deletes get d to finish); false if they didn't.
func (h *Hub) WaitTimeout(d time.Duration) bool {
	done := make(chan struct{})
	go func() {
		h.bg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}

func (h *Hub) goBackground(fn func()) {
	h.bg.Add(1)
	go func() {
		defer h.bg.Done()
		fn()
	}()
}

// Domain returns the configured base domain.
func (h *Hub) Domain() string { return h.cfg.Domain }

func (h *Hub) statePath() string        { return filepath.Join(h.cfg.DataDir, "state.yaml") }
func (h *Hub) policyPath() string       { return filepath.Join(h.cfg.DataDir, "group-gate-policy.json") }
func (h *Hub) attributesPath() string   { return filepath.Join(h.cfg.DataDir, policy.UserAttributesFile) }
func (h *Hub) envPath(id string) string { return filepath.Join(h.cfg.DataDir, "env", id+".env") }
func (h *Hub) overridePath(id string) string {
	return filepath.Join(h.cfg.DataDir, "overrides", id+".override.yml")
}

// userOverridePath is the app's custom override (Expert mode): kept by the
// Hub, outside the template clone, so template syncs never touch it.
func (h *Hub) userOverridePath(id string) string {
	return filepath.Join(h.cfg.DataDir, "overrides", id+".user.yml")
}
func (h *Hub) templatesRoot() string { return filepath.Join(h.cfg.ProjectDir, "templates") }
func projectName(id string) string   { return ProjectPrefix + id }

// saveLocked persists state. Caller must hold mu (write).
func (h *Hub) saveLocked() {
	if err := h.st.Save(h.statePath()); err != nil {
		log.Printf("ERROR: save state: %v", err)
	}
}

// ── errors ───────────────────────────────────────────────

// StatusError carries the HTTP status an error should map to.
type StatusError struct {
	Status int
	Err    error
}

func (e *StatusError) Error() string { return e.Err.Error() }
func (e *StatusError) Unwrap() error { return e.Err }

// statusErr is a StatusError of code with the formatted message. An
// argument that is the engine guard's refusal (docker.ErrEngineRefused,
// contract §6) makes it a 503 that still unwraps to the refusal, whatever
// code the call site chose for an engine failure.
func statusErr(code int, format string, args ...interface{}) error {
	err := fmt.Errorf(format, args...)
	for _, a := range args {
		if e, ok := a.(error); ok && errors.Is(e, docker.ErrEngineRefused) {
			return &StatusError{Status: http.StatusServiceUnavailable, Err: &wrappedErr{msg: err.Error(), err: e}}
		}
	}
	return &StatusError{Status: code, Err: err}
}

// wrappedErr is msg, unwrapping to err.
type wrappedErr struct {
	msg string
	err error
}

func (e *wrappedErr) Error() string { return e.msg }
func (e *wrappedErr) Unwrap() error { return e.err }

// ErrNotFound is returned for unknown template IDs.
var ErrNotFound = &StatusError{Status: http.StatusNotFound, Err: errors.New("not found")}

// ── catalog ──────────────────────────────────────────────

// coreCheckoutBindLocked: t binds (any mode) an absolute host path at,
// inside or above the core checkout's host path (ProjectHostDir, the
// --project-directory every compose run uses): the template could read
// or rewrite core's files. Folded paths count too (pathsNear).
func (h *Hub) coreCheckoutBindLocked(t *templates.Template) (templates.BindSource, bool) {
	core := h.cfg.ProjectHostDir
	if core == "" || !strings.HasPrefix(core, "/") {
		return templates.BindSource{}, false
	}
	core = path.Clean(core)
	for _, b := range templates.AbsoluteBindSources(t.ReadCompose()) {
		if pathsNear(path.Clean(b.Source), core) {
			return b, true
		}
	}
	return templates.BindSource{}, false
}

// Discover rebuilds the template catalog from the configured sources.
func (h *Hub) Discover() {
	h.mu.Lock()
	defer h.mu.Unlock()
	var ts []templates.Template
	for _, src := range h.st.Sources {
		if src.Path != "" {
			ts = append(ts, templates.Discover(src.Path, src.Name, h.cfg.Domain, h.kinds)...)
		}
	}
	h.allTemplates = append([]templates.Template(nil), ts...)
	h.templateIDs = map[string]bool{}
	for _, t := range ts {
		h.templateIDs[t.ID] = true
	}
	// The first source wins on duplicate IDs: two templates with the same
	// ID would share a compose project, env file and policy keys.
	seen := map[string]bool{}
	var uniq []templates.Template
	for _, t := range ts {
		if seen[t.ID] {
			log.Printf("Skipping template %s from source %s: ID already provided by another source", t.ID, t.Source)
			continue
		}
		if sub := coreSubdomain(t.Subdomains); sub != "" {
			log.Printf("Skipping template %s: it routes core subdomain %q", t.ID, sub)
			continue
		}
		if b, ok := h.coreCheckoutBindLocked(&t); ok {
			log.Printf("Skipping template %s: service %s binds %s, at, inside or above the core checkout (%s)", t.ID, b.Service, b.Source, h.cfg.ProjectHostDir)
			continue
		}
		if e, ok := h.st.Instances[t.ID]; ok && e.Template != t.ID {
			log.Printf("Skipping template %s: its id is already an instance of %s", t.ID, e.Template)
			continue
		}
		seen[t.ID] = true
		uniq = append(uniq, t)
	}
	// A template whose default names (project, volumes, groups, Keycloak
	// clients) an existing instance of another template already derives
	// would share them: the instance was there first.
	// Two templates' default instances may not share a volume or a Traefik
	// name (defaultClaims): enabled ones claim first, then those whose
	// default instance has any other state (settings, policies, ops
	// record, …) — a disabled installed app keeps its names against a
	// newcomer —, then source order.
	tier := map[string]int{}
	for _, t := range uniq {
		tier[t.ID] = h.claimTierLocked(t.ID)
	}
	sort.SliceStable(uniq, func(i, j int) bool { return tier[uniq[i].ID] > tier[uniq[j].ID] })
	// byID points into uniq: build it only after the sort, which moves the
	// elements (pointers taken before would name the wrong templates).
	byID := map[string]*templates.Template{}
	for i := range uniq {
		byID[uniq[i].ID] = &uniq[i]
	}
	claimed := map[string]string{}
	kept := make([]templates.Template, 0, len(uniq))
	for _, t := range uniq {
		if c := h.claimCollision(&t, byID); c != "" {
			log.Printf("Skipping template %s: its default instance would use the %s", t.ID, c)
			continue
		}
		cs := defaultClaims(&t)
		if c, who := firstClaimed(cs, claimed); who != "" {
			kind, name, _ := strings.Cut(c, "\x00")
			log.Printf("Skipping template %s: its default instance would use the %s %s of the default instance of %s", t.ID, kind, name, who)
			continue
		}
		for _, c := range cs {
			claimed[c] = t.ID
		}
		kept = append(kept, t)
	}
	uniq = kept
	templates.Sort(uniq)
	h.templates = uniq
	h.catalogGen++
	h.rebuildLocked()
	for _, id := range h.st.Enabled {
		if h.findLocked(id) == nil {
			log.Printf("WARNING: enabled app %s has no (valid) template any more — its containers keep running; disable it to stop them", id)
		}
	}
	if h.refreshPublishedLocked() {
		h.saveLocked()
	}
}

// claimTierLocked ranks a template's default instance for Discover's
// claims: 2 enabled, 1 any other state in state.yaml or an ops record, 0
// none (a newcomer). Caller must hold mu.
func (h *Hub) claimTierLocked(id string) int {
	if h.st.IsEnabled(id) {
		return 2
	}
	_, a := h.st.Settings[id]
	_, c := h.st.Published[id]
	_, d := h.st.PublicAccess[id]
	_, e := h.st.PublicMode[id]
	_, f := h.st.PublicTokens[id]
	_, g := h.st.SignInMode[id]
	_, i := h.st.Instances[id]
	h.opsMu.Lock()
	_, o := h.ops[id]
	h.opsMu.Unlock()
	if a || c || d || e || f || g || i || o {
		return 1
	}
	return 0
}

// snapshot captures what an enabled instance publishes to group-gate (v6).
// Caller must hold mu.
func (h *Hub) snapshot(t *templates.Template) state.PublishedApp {
	a := t.Manifest.Auth
	acc := h.accessLocked(t)
	users, admins := h.instanceGroupsLocked(t)
	p := state.PublishedApp{
		Hosts:           slices.Sorted(maps.Values(t.Hosts)),
		GroupAccess:     acc.groupAccess(t),
		NativeLoginOnly: acc.SignIn == SignInNative,
		AccessGroup:     users,
		AdminGroup:      admins,
		AdminPaths:      append([]string(nil), a.AdminPaths...),
	}
	n := t.NamesFor(t.ID)
	p.Traefik = append([]string(nil), n.Traefik...)
	p.Volumes = slices.Sorted(maps.Values(n.Volumes))
	p.Clients = append([]string(nil), n.Clients...)
	for _, name := range headerNames(&t.Manifest) {
		if sfx := headerSuffix(name); !slices.Contains(p.HeaderSuffixes, sfx) {
			p.HeaderSuffixes = append(p.HeaderSuffixes, sfx)
		}
	}
	slices.Sort(p.HeaderSuffixes)
	if acc.Capability.Templates {
		p.SignInTemplate = h.st.Instances[t.ID].SignInTemplate
	}
	if acc.Capability.Enforcement == policy.EnforceAtLogin {
		p.SignInClients = signInClientIDs(t)
	}
	if pub := h.publicLocked(t, t.Public); pub.Active() {
		p.PublicHosts = slices.Sorted(slices.Values(t.Public.Hosts))
		p.Public = publicEntry(&t.Manifest, pub.Published)
	}
	return p
}

// refreshPublishedLocked brings state.Published in line with the catalog:
// enabled apps whose template loads get a fresh snapshot, apps that are no
// longer enabled lose theirs, and enabled apps whose template is missing
// keep their last known one. Returns whether anything changed. Caller must
// hold mu (write).
func (h *Hub) refreshPublishedLocked() bool {
	changed := false
	for id := range h.st.Published {
		if !h.st.IsEnabled(id) {
			delete(h.st.Published, id)
			changed = true
		}
	}
	for _, id := range h.st.Enabled {
		t := h.findLocked(id)
		if t == nil {
			continue
		}
		snap := h.snapshot(t)
		if old, ok := h.st.Published[id]; !ok || !reflect.DeepEqual(old, snap) {
			h.st.Published[id] = snap
			changed = true
		}
	}
	return changed
}

// findLocked returns a pointer into the instance views (by instance id;
// a template id names its default instance). Caller must hold mu.
func (h *Hub) findLocked(id string) *templates.Template {
	for i := range h.instances {
		if h.instances[i].ID == id {
			return &h.instances[i]
		}
	}
	return nil
}

// Template returns a copy of an instance's view (nil if unknown).
func (h *Hub) Template(id string) *templates.Template {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if t := h.findLocked(id); t != nil {
		c := *t
		return &c
	}
	return nil
}

// Templates returns a copy of the catalog.
func (h *Hub) Templates() []templates.Template {
	h.mu.RLock()
	ts := append([]templates.Template(nil), h.templates...)
	h.mu.RUnlock()
	// Under podman, each with its rootless verdict (contract §11.10).
	return h.withRootless(ts)
}

// Sources returns a copy of the configured sources.
func (h *Hub) Sources() []state.Source {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return append([]state.Source(nil), h.st.Sources...)
}

// Counts summarises the catalog for /api/status.
func (h *Hub) Counts() (templates, enabled, sources int) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.templates), len(h.st.Enabled), len(h.st.Sources)
}

// IsEnabled reports whether id is enabled.
func (h *Hub) IsEnabled(id string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.st.IsEnabled(id)
}

// ── group-gate policy file ───────────────────────────────

// WritePolicy regenerates, in this order, signin-keycloak.json
// (signin_publish.go), group-gate-policy.json, user-attributes.json and
// portal-apps.json from current state, and in the same pass mcp-gate.json
// and the caller secrets of mcp-credentials.json (ai_gatefile.go). Takes
// mu itself — callers must NOT hold it.
func (h *Hub) WritePolicy() error {
	_, err := h.writePolicy()
	return err
}

// writePolicy is WritePolicy; attrs: user-attributes.json was written
// (or removed) — false when the directory failed and the file was kept.
func (h *Hub) writePolicy() (attrsWritten bool, retErr error) {
	// Serialise snapshot → rename so an older snapshot can never overwrite a
	// newer one (a stale file could drop groups and fail open).
	h.policyWriteMu.Lock()
	defer h.policyWriteMu.Unlock()
	// Directory state first: it is network I/O, never under h.mu.
	// One directory read, never under mu (G47): the policy file and the
	// gate file are built from the same snapshot.
	dr := h.directoryState()
	expiring, attrs, keepAttrs := dr.expiring, dr.attrs, dr.keepAttrs
	// The passkey trust list (reads the extra-authenticators file: before mu).
	trust, mdsDoc := h.signInTrust()
	h.driftMu.Lock()
	runtime := make(map[string][]string, len(h.runtimeHosts))
	for id, hosts := range h.runtimeHosts {
		runtime[id] = hosts
	}
	h.driftMu.Unlock()

	h.mu.RLock()
	mainDomain := h.cfg.Domain
	coreHosts := policy.CoreHosts(mainDomain)
	enrolled := h.enrolledLocked()
	extraDomains := make([]string, 0, len(enrolled))
	for _, d := range enrolled {
		extraDomains = append(extraDomains, d.Name)
	}
	apps := make([]policy.App, 0, len(h.instances))
	covered := map[string]bool{}
	for i := range h.instances {
		t := &h.instances[i]
		if !t.Enabled {
			continue
		}
		covered[t.ID] = true
		// Router-less instances (contract §3, §4): publish no hosts, groups
		// or template. They have no routers, so no hostnames, and get no
		// Keycloak client or access role.
		if t.Manifest.Routerless() {
			continue
		}
		users, admins := h.instanceGroupsLocked(t)
		acc := h.accessLocked(t)
		app := policy.App{
			ID:          t.ID,
			Enabled:     true,
			Hosts:       hostSet(slices.Collect(maps.Values(t.Hosts)), coreHosts),
			GroupAccess: acc.groupAccess(t),
			AccessGroup: users,
			AdminGroup:  admins,
			AdminPaths:  t.Manifest.Auth.AdminPaths,
		}
		if acc.Capability.Templates {
			app.Template = h.st.Instances[t.ID].SignInTemplate
		}
		if pub := h.publicLocked(t, t.Public); pub.Active() {
			app.PublicHosts, app.Public = hostSet(t.Public.Hosts, coreHosts), publicEntry(&t.Manifest, pub.Published)
		}
		apps = append(apps, app)
	}
	for _, id := range h.st.Enabled {
		if covered[id] {
			continue
		}
		covered[id] = true
		// A snapshot without a (non-core) host is unknown config: it would
		// publish nothing for the hosts the containers still route, so it
		// falls through to the deny path below (fail closed).
		snap, ok := h.st.Published[id]
		var snapHosts map[string]string
		if ok {
			snapHosts = hostSet(snap.Hosts, coreHosts)
		}
		if len(snapHosts) > 0 {
			log.Printf("auth-policy: WARNING: template for enabled app %s is missing — still enforcing its last known config (hosts %v)", id, snap.Hosts)
			apps = append(apps, policy.App{
				ID:          id,
				Enabled:     true,
				Hosts:       snapHosts,
				GroupAccess: snap.GroupAccess,
				AccessGroup: snap.AccessGroup,
				AdminGroup:  snap.AdminGroup,
				AdminPaths:  snap.AdminPaths,
				// The containers keep the public router they were started
				// with: keep showing it.
				PublicHosts: hostSet(snap.PublicHosts, coreHosts),
				Public:      snap.Public,
				Template:    snap.SignInTemplate,
			})
			continue
		} else if ok {
			log.Printf("auth-policy: WARNING: template for enabled app %s is missing and its last known config has no hostnames — treating it as unknown (deny)", id)
		}
		// No config: its running hosts are denied by the loop below.
		if len(hostSet(runtime[id], coreHosts)) == 0 {
			log.Printf("auth-policy: WARNING: enabled app %s has neither a template nor a last known config, and no routed hosts are known yet — cannot publish a deny entry", id)
		}
	}
	// Every host a running app project routes that no known config claims
	// is denied (any domain): projects that are not enabled (drift), but
	// also enabled ones whose containers still route hosts outside their
	// config — old hostnames after a SetHosts whose restart failed, hosts
	// outside a missing template's snapshot. Build skips claimed hosts.
	for id, rh := range runtime {
		if hosts := hostSet(rh, coreHosts); len(hosts) > 0 {
			apps = append(apps, policy.App{ID: id, Enabled: true, Deny: true, Hosts: hosts})
		}
	}
	doc := policy.Build(policy.BuildInput{
		Apps: apps, Default: h.st.SignIn.Default, Core: maps.Clone(h.st.SignIn.Core),
		Templates: h.publishedTemplatesLocked(), Methods: h.methodsOnLocked(),
		People: h.peopleMethodsLocked(), AddStronger: h.st.SignIn.AddStronger,
		MainDomain: mainDomain, ExtraDomains: extraDomains,
	})
	doc.Expiring = expiring
	doc.VPN = h.vpnPolicyLocked()
	kcSignIn := h.keycloakSignInLocked()
	kcSignIn.Authenticators, kcSignIn.MDS = trust, mdsDoc
	portal := h.portalLocked()
	// The header deliveries (§4.1 hosts): enabled instances with a view,
	// on the hosts their routers gate now.
	hosts, suppress := h.publishedHostHeadersLocked()
	// impersonation.json follows every instance or client change (D37,
	// F30): written here, under mu, from the same clients.
	impErr := h.writeImpersonationFileLocked()
	h.mu.RUnlock()
	// The Keycloak extension's file first (contract §8.1): a sign-in
	// change reaches the native-OIDC logins before group-gate's file. A
	// failed write never skips group-gate's file: both are attempted and
	// their errors joined (each reader keeps failing closed on its own).
	kcErr := writeKeycloakSignIn(h.signInKeycloakPath(), kcSignIn)
	if err := policy.Write(h.policyPath(), doc); err != nil {
		return false, errors.Join(kcErr, err)
	}
	h.lastExpiring = expiring
	errs := []error{kcErr, impErr}
	switch {
	case keepAttrs:
		// The directory's fields and users stay as published; the hosts
		// section (header deliveries, from their own snapshots) follows,
		// so a demotion still reaches group-gate. No readable v2 file:
		// kept as it is.
		written, err := h.replaceAttrHosts(hosts, suppress)
		attrsWritten = written
		if err != nil {
			errs = append(errs, err)
		}
	case attrs == nil && len(hosts) == 0 && len(suppress) == 0:
		attrsWritten = true
		if err := os.Remove(h.attributesPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	default:
		out := policy.BuildUserAttributes(nil, nil, nil)
		if attrs != nil {
			out = *attrs
		}
		out.Hosts = policy.BuildHosts(hosts)
		policy.SuppressFieldHeaders(&out, suppress)
		if err := policy.WriteUserAttributes(h.attributesPath(), out); err != nil {
			errs = append(errs, err)
		} else {
			attrsWritten = true
		}
	}
	// The landing portal's app list (contract §10) changes exactly when
	// the policy does: enable, disable, template sync.
	errs = append(errs, writePortal(h.portalPath(), portal))
	// The gate files follow in the same pass (contract §15.4).
	errs = append(errs, h.writeGateFiles(dr.m, dr.mErr))
	// Leavers' credentials are marked revoking in this same pass, from
	// this snapshot (§15.5; no hook here: the AI reconcile loop revokes).
	if dr.m != nil {
		h.markLeavers(dr.m)
	}
	return attrsWritten, errors.Join(errs...)
}

// hostSet is the policy.App host set of hosts (normalised), core hosts
// left out: they come from group-gate-map.conf (contract §4).
// Invalid hostnames (contract §4 key shape) are dropped and logged: group-gate
// would deny the whole file on such a key.
func hostSet(hosts []string, core map[string]bool) map[string]string {
	out := make(map[string]string, len(hosts))
	for _, host := range hosts {
		n := NormalizeHost(host)
		switch {
		case core[n]:
		case !templates.ValidHostname(n):
			log.Printf("auth-policy: %q is not a valid hostname — not published", host)
		default:
			out[n] = n
		}
	}
	return out
}

func coreSubdomain(subs []string) string {
	coreSubs := policy.CoreSubdomains()
	for _, s := range subs {
		if coreSubs[s] {
			return s
		}
	}
	return ""
}

func (h *Hub) writePolicyLogged() {
	if err := h.WritePolicy(); err != nil {
		log.Printf("auth-policy: group-gate policy write failed: %v", err)
	}
}
