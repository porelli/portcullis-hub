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
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/portcullis/hub/internal/compose"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/docker"
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
}

// IdP manages the OIDC clients templates declare.
type IdP interface {
	RegisterClient(ctx context.Context, s keycloak.ClientSpec) error
	UpdateClientACR(ctx context.Context, s keycloak.ClientSpec) error
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
	// freshAuth verifies fresh-auth proofs (freshauth.go; nil: refused).
	freshAuth FreshAuth
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

	// bg tracks background lifecycle work (queued restarts, default-policy
	// propagation) so callers can wait for it.
	bg sync.WaitGroup

	policyWriteMu   sync.Mutex
	defaultPolicyMu sync.Mutex

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

	// Directory publishing (SetDirectory). lastExpiring is the expiring
	// list last written (guarded by policyWriteMu; nil: not yet known).
	dirState DirectoryState
	attrSync func(ctx context.Context) error
	// freshAuthEnsure re-asserts the fresh-auth Keycloak client in the
	// directory sync loop (freshauth.go); under policyWriteMu like attrSync.
	freshAuthEnsure func(ctx context.Context) error
	lastExpiring    []policy.Expiring
	dirKick         chan struct{}

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
		credKick:             make(chan struct{}, 1),
		driftKey:             map[string]string{},
		afterFunc:            realAfterFunc,
		sleep:                realSleep,
		mountinfo:            func() ([]byte, error) { return os.ReadFile("/proc/self/mountinfo") },
		lookupIP:             defaultLookupIP,
		idRanges:             templates.PersonIDPools,
	}
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
	return h, nil
}

// Init removes backup / restore leftovers (SweepBackupLeftovers), clones
// the default source on first run, discovers templates, syncs the git
// sources (Config.SyncSourcesAtStart; fail-safe, sources.go), rolls back
// interrupted restores in the background (RecoverRestores) and seeds the
// group-gate policy file.
func (h *Hub) Init() {
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
	// Interrupted same-instance restores are rolled back (background).
	h.RecoverRestores()
	// Interrupted shared-folder applies and undos: their stopped apps are
	// started again with what state.yaml holds (background; never a
	// fixer run, contract §14.3).
	h.RecoverFolderApplies()
	// The header deliveries group-gate serves now: what the first policy
	// write publishes again (P13).
	h.seedHostHeaders()
	if err := h.WritePolicy(); err != nil {
		log.Printf("auth-policy: initial group-gate policy write failed: %v", err)
	}
	// Reloads and restarts committed changes still owe (the previous run
	// stopped before applying them): queued again.
	h.initStage("requeue")
	h.requeueOwed()
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

func statusErr(code int, format string, args ...interface{}) error {
	return &StatusError{Status: code, Err: fmt.Errorf(format, args...)}
}

// ErrNotFound is returned for unknown template IDs.
var ErrNotFound = &StatusError{Status: http.StatusNotFound, Err: errors.New("not found")}

// ── catalog ──────────────────────────────────────────────

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
	_, b := h.st.AuthPolicies[id]
	_, c := h.st.Published[id]
	_, d := h.st.PublicAccess[id]
	_, e := h.st.PublicMode[id]
	_, f := h.st.PublicTokens[id]
	_, g := h.st.SignIn[id]
	_, i := h.st.Instances[id]
	h.opsMu.Lock()
	_, o := h.ops[id]
	h.opsMu.Unlock()
	if a || b || c || d || e || f || g || i || o {
		return 1
	}
	return 0
}

// snapshot captures what an enabled instance publishes to group-gate (v5).
// Caller must hold mu.
func (h *Hub) snapshot(t *templates.Template) state.PublishedApp {
	a := t.Manifest.Auth
	acc := h.accessLocked(t)
	p := state.PublishedApp{
		Hosts:           slices.Sorted(maps.Values(t.Hosts)),
		GroupAccess:     acc.groupAccess(t),
		NativeLoginOnly: acc.SignIn == SignInNative,
		AccessGroup:     a.AccessGroup,
		AdminGroup:      a.AdminGroup,
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
	if ov, ok := h.st.AuthPolicies[t.ID]; ok {
		ov.Factors = append([]string(nil), ov.Factors...)
		p.Policy = &ov
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
	defer h.mu.RUnlock()
	return append([]templates.Template(nil), h.templates...)
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

// WritePolicy regenerates group-gate-policy.json from current state. Takes
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
	expiring, attrs, keepAttrs := h.directoryState()
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
	perApp := make(map[string]policy.AuthPolicy, len(h.st.AuthPolicies))
	for k, v := range h.st.AuthPolicies {
		perApp[k] = v
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
		// or policy. They have no routers, so no hostnames, and get no
		// Keycloak client or access role.
		if t.Manifest.Routerless() {
			continue
		}
		app := policy.App{
			ID:          t.ID,
			Enabled:     true,
			Hosts:       hostSet(slices.Collect(maps.Values(t.Hosts)), coreHosts),
			GroupAccess: h.accessLocked(t).groupAccess(t),
			AccessGroup: t.Manifest.Auth.AccessGroup,
			AdminGroup:  t.Manifest.Auth.AdminGroup,
			AdminPaths:  t.Manifest.Auth.AdminPaths,
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
			if _, ok := perApp[id]; !ok && snap.Policy != nil {
				perApp[id] = *snap.Policy
			}
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
	doc := policy.Build(apps, perApp, h.st.Default(), mainDomain, extraDomains)
	doc.Expiring = expiring
	portal := h.portalLocked()
	// The header deliveries (§4.1 hosts): enabled instances with a view,
	// on the hosts their routers gate now.
	hosts, suppress := h.publishedHostHeadersLocked()
	h.mu.RUnlock()
	if err := policy.Write(h.policyPath(), doc); err != nil {
		return false, err
	}
	h.lastExpiring = expiring
	var errs []error
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
