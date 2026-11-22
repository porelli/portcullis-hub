package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/portcullis/hub/internal/meshplan"
	"github.com/portcullis/hub/internal/nminus1"
	"github.com/portcullis/hub/internal/nodeadm"
	"github.com/portcullis/hub/internal/servers"
	"github.com/portcullis/hub/internal/state"
)

// The HA page (contract §20.1 "The HA page", D4, D5, D13): Settings →
// High availability, admin, Kubernetes only; MCP ha_status (R); the CLI
// twin GET /host/ha (`hub ha checklist`). It is read-only: the checklist
// `./portcullis ha enable` needs all green, the live state (quorum,
// sites, N−1 per node, the front door and its worst-case texts, fencing,
// volumes) and the command. Turning HA on is CLI-only (D5): there is no
// enable route. Its reads are a nodeadm snapshot (GET, through
// fsutil.Do: the write fence lets reads through while this Hub stands
// by) and frontdoor-status (a ConfigMap get, also a read), shared by
// concurrent refreshes under the key opKeyHA. The Hub never sees the
// front door's DNS credentials nor the backup destination's: the
// destination is presence only (HUB_BACKUP_DESTINATION=set from core's
// chart, contract §2, pre-flight P43), and the main domain's DNS
// provider is its id only (HUB_DNS_PROVIDER from core's chart, else
// core.env's DNS_PROVIDER, both ^[a-z0-9-]{1,32}$; else unknown). The
// destination is never read from core.env. A nodeadm
// failure degrades the page: every snapshot item is red with the reason,
// and the banner, the command and the other items are still answered.

// opKeyHA keys the HA page's refreshes (one snapshot read at a time,
// shared by every caller waiting on it). It is never an op record.
const opKeyHA = "_ha"

// HAExperimentalBanner is the page's banner (D13).
const HAExperimentalBanner = "High availability is experimental"

// HACommand is the CLI-only conversion (D5).
const HACommand = "./portcullis ha enable"

// The guarantee texts (spec §7.2, verbatim).
const (
	GuaranteeZeroLoss = "Zero loss on one failure"
	GuaranteeDegraded = "Degraded: one more failure may lose the last writes"
)

// PorkbunCredentialsNote: Porkbun's API keys are account-wide (Global
// Constraints, credentials Q1).
const PorkbunCredentialsNote = "Porkbun API keys can change every domain in the account: Portcullis can't narrow them"

// EnrollKnownGap: enroll stays at 1 replica in HA (Task 19 ruling 1).
const EnrollKnownGap = "Device enrolment (enroll) runs as one copy in HA: while its node is down, new invites and certificate enrolments wait until it is back on another node. Sign-in itself keeps working."

// The checklist texts (contract §20.1, each while its item isn't ok).
const (
	haTextNodes      = "at least 3 nodes"
	haTextServers    = "at least 3 servers"
	haTextStorage    = "at least 2 storage nodes (3 recommended)"
	haTextIngress    = "at least 1 ingress node (2 recommended)"
	haTextBackup     = "set an offsite backup destination first"
	haTextNMinus1    = "the N−1 check isn't green"
	haTextWatchdogF  = "node %s has no watchdog: fencing can't be confirmed"
	haTextFrontdoorF = "the front door's status isn't readable: %s"
)

// haTextSnapshotF: every snapshot item while nodeadm's snapshot can't be
// read (fail closed: never green without it).
const haTextSnapshotF = "nodeadm's snapshot isn't readable: %s"

// haTextUnconfirmedF: a site whose only reachable candidate is offered,
// not confirmed by another site's dial-in (§20.11).
const haTextUnconfirmedF = "site %s: its endpoint isn't confirmed yet"

// HAItem is one checklist item.
type HAItem struct {
	ID   string `json:"id"`
	OK   bool   `json:"ok"`
	Text string `json:"text"`
}

// HANode is one node of the page.
type HANode struct {
	Name    string        `json:"name"`
	Role    string        `json:"role"`
	Class   string        `json:"class"`
	Site    string        `json:"site"`
	Ready   bool          `json:"ready"`
	Fencing bool          `json:"fencing"`
	NMinus1 nminus1.Level `json:"n_minus_1"`
}

// HADNSSite is one site of a name: whether one of its ingress nodes is
// ok, and the worst case if it fails; its ingress nodes, which of the
// name's published addresses are its (frontdoor-status sites.<s>.
// addresses, plan Task 28) and how many of its probers were blind in the
// front door's last round (its uplink lost).
type HADNSSite struct {
	Site          string   `json:"site"`
	Healthy       bool     `json:"healthy"`
	WorstCaseText string   `json:"worst_case_text"`
	Ingress       []string `json:"ingress"`
	Addresses     []string `json:"addresses"`
	BlindProbers  int      `json:"blind_probers"`
}

// HADNS is one name the front door publishes.
type HADNS struct {
	Name          string      `json:"name"`
	Addresses     []string    `json:"addresses"`
	WorstCaseText string      `json:"worst_case_text"`
	PerSite       []HADNSSite `json:"per_site"`
}

// HAFrontdoor is the front door's own state: leading or standing by
// (frontdoor-status' state, §20.5), "" with Error when it can't be read
// (or "" and no error without HA: the front door runs only in HA).
type HAFrontdoor struct {
	State string `json:"state"`
	Error string `json:"error"`
	// SnapshotStale: the front door's last round couldn't read nodeadm's
	// snapshot, so the per-site view is the one of SnapshotAt (core Task
	// 28 fix round 1: it keeps the last sites, never an empty view).
	SnapshotStale bool   `json:"snapshot_stale"`
	SnapshotAt    string `json:"snapshot_at"`
}

// HAView is GET /api/ha (and GET /host/ha). Frontdoor, Volumes,
// Warnings and KnownGaps go beyond the contract's example shape (the
// page's live state, the rulings' notes).
type HAView struct {
	Experimental    bool             `json:"experimental"`
	Enabled         bool             `json:"enabled"`
	Checklist       []HAItem         `json:"checklist"`
	Guarantee       string           `json:"guarantee"`
	Nodes           []HANode         `json:"nodes"`
	Quorum          nodeadm.Quorum   `json:"quorum"`
	Sites           []SiteView       `json:"sites"`
	DNS             []HADNS          `json:"dns"`
	CredentialsNote string           `json:"credentials_note"`
	Command         string           `json:"command"`
	Frontdoor       HAFrontdoor      `json:"frontdoor"`
	Volumes         []nodeadm.Volume `json:"volumes"`
	Warnings        []string         `json:"warnings"`
	KnownGaps       []string         `json:"known_gaps"`
}

// haPage is the page's wiring: the shared refreshes and the
// frontdoor-status reader (nil: the kube backend's; tests set one).
type haPage struct {
	reads     singleflight.Group
	frontdoor func(ctx context.Context) ([]byte, error)
	// The doctor's HA inputs (doctor_ha.go; nil: the defaults): the last
	// successful core backup, the write fence and the dial of a node's
	// public API and kubelet ports.
	lastBackup func(ctx context.Context) (*time.Time, error)
	lease      func() error
	dialAPI    func(ctx context.Context, addr string) bool
	// doctorWait: the doctor's wait on the shared read (0: doctorHAWait).
	doctorWait time.Duration
	// api caches the API-port dials (doctor_ha.go).
	api apiCache
}

// haReadWait bounds one shared refresh (the snapshot and the status).
const haReadWait = 20 * time.Second

// SetFrontdoorStatus replaces the frontdoor-status reader (tests).
func (h *Hub) SetFrontdoorStatus(f func(ctx context.Context) ([]byte, error)) { h.ha.frontdoor = f }

// frontdoorStatusReader is the kube backend's read of frontdoor-status.
type frontdoorStatusReader interface {
	FrontdoorStatus(ctx context.Context) ([]byte, error)
}

func (h *Hub) readFrontdoorStatus(ctx context.Context) ([]byte, error) {
	if f := h.ha.frontdoor; f != nil {
		return f(ctx)
	}
	if r, ok := unwrapRT(h.rt).(frontdoorStatusReader); ok {
		return r.FrontdoorStatus(ctx)
	}
	return nil, errors.New("no Kubernetes client")
}

// ErrTextHANeedsKube is the refusal off Kubernetes (Docker and Podman
// don't change at all, §20).
const ErrTextHANeedsKube = "high availability needs Kubernetes"

// HAOn refuses (409) the page off Kubernetes.
func (h *Hub) HAOn() error {
	if !h.kubeOn() {
		return statusErr(http.StatusConflict, "%s", ErrTextHANeedsKube)
	}
	return nil
}

// haRead is one refresh's reads.
type haRead struct {
	snap      nodeadm.Snapshot
	snapErr   error
	status    []byte
	statusErr error
}

// HA is GET /api/ha: a fresh snapshot (shared by concurrent refreshes),
// judged now. Read-only.
func (h *Hub) HA(ctx context.Context) (*HAView, error) {
	if err := h.HAOn(); err != nil {
		return nil, err
	}
	r, err := h.haShared(ctx)
	if err != nil {
		return nil, err
	}
	return h.haView(r), nil
}

// haShared is one shared refresh's reads (the HA page's and the
// doctor's: one snapshot read at a time).
func (h *Hub) haShared(ctx context.Context) (*haRead, error) {
	return h.haSharedWait(ctx, 0)
}

// haSharedWait is haShared waiting at most wait (0: until the read ends,
// itself bounded by haReadWait); on a timeout the read goes on for the
// other waiters.
func (h *Hub) haSharedWait(ctx context.Context, wait time.Duration) (*haRead, error) {
	var timeout <-chan time.Time
	if wait > 0 {
		t := time.NewTimer(wait)
		defer t.Stop()
		timeout = t.C
	}
	ch := h.ha.reads.DoChan(opKeyHA, func() (v any, err error) {
		// singleflight re-panics in its own goroutine, out of net/http's
		// recover: a panic here would end the Hub (the single writer).
		defer func() {
			if p := recover(); p != nil {
				log.Printf("ha: the HA read panicked: %v", p)
				v, err = nil, fmt.Errorf("the HA read failed: %v", p)
			}
		}()
		return h.haReadOnce(ctx), nil
	})
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timeout:
		return nil, fmt.Errorf("nodeadm didn't answer within %s", wait)
	case res := <-ch:
		if res.Err != nil {
			return nil, res.Err
		}
		return res.Val.(*haRead), nil
	}
}

// haReadOnce is the shared read: the snapshot (its error kept: the page
// degrades) and, in HA, frontdoor-status. It outlives one caller's
// cancel (another may wait on it), never haReadWait.
func (h *Hub) haReadOnce(ctx context.Context) *haRead {
	c, cancel := context.WithTimeout(context.WithoutCancel(ctx), haReadWait)
	defer cancel()
	r := &haRead{}
	if api, err := h.nodeadmAPI(c); err != nil {
		r.snapErr = err
	} else if r.snap, err = h.clusterSnapshot(c, api); err != nil {
		r.snapErr = nodeadmErr(err)
	}
	if h.cfg.HA {
		r.status, r.statusErr = h.readFrontdoorStatus(c)
	}
	return r
}

// haPlace is a managed node's placement from the Hub's records.
type haPlace struct {
	site, class      string
	ingress, storage bool
}

// haPlacement is each managed node's site, class, ingress and storage:
// its Server entry, else (a node of init, pinned in the mesh records)
// its Node's labels. A node the Hub has no record of isn't placed (it
// counts for nothing on the checklist; the sites view flags it).
func (h *Hub) haPlacement(snap nodeadm.Snapshot) map[string]haPlace {
	site, ingress, _ := h.nodeSites(snap)
	out := map[string]haPlace{}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, n := range snap.Nodes {
		s, ok := site[n.Name]
		if !ok {
			continue
		}
		p := haPlace{site: s, ingress: ingress[n.Name], class: n.Labels[nodeadm.LabelClass], storage: n.Labels[nodeadm.LabelStorage] == "true"}
		if e, listed := h.st.Servers[n.Name]; listed && e.ClusterNode() {
			p.class = nonEmpty(e.Class, p.class)
			p.storage = e.Labels != nil && e.Labels.Storage
		}
		out[n.Name] = p
	}
	return out
}

// replicatedTier: pod p is (or becomes in HA) a replicated-tier pod, so
// its node must fence before it moves: a core pod (but a DaemonSet's, or
// one at normal or low priority, whose data is local or rebuildable) or
// an app at critical or high (§20.6).
func replicatedTier(p *nodeadm.Pod, ns nminus1.Namespaces) bool {
	if p.DaemonSet {
		return false
	}
	switch p.Namespace {
	case ns.Core:
		return p.PriorityClass != "portcullis-normal" && p.PriorityClass != "portcullis-low"
	case ns.Apps:
		return p.PriorityClass == "portcullis-critical" || p.PriorityClass == "portcullis-high"
	}
	return false
}

// Guarantee is the page's Postgres guarantee: zero loss with a
// synchronous standby (2 or more instances), else degraded.
func Guarantee(pg nodeadm.Postgres) string {
	if pg.Instances >= 2 && pg.SyncStandbys >= 1 {
		return GuaranteeZeroLoss
	}
	return GuaranteeDegraded
}

// haIn is what the checklist judges: the snapshot, the Hub's placement,
// the N−1 results (n1Err: the check's refusal), the sites view, the sites
// with a confirmed reachable node, the round trips, the backup
// destination's presence and whether HA is on.
type haIn struct {
	snap      nodeadm.Snapshot
	place     map[string]haPlace
	n1        []nminus1.Result
	n1Err     string
	sites     []SiteView
	confirmed map[string]bool
	rtt       map[string]map[string]int
	backup    bool
	enabled   bool
	ns        nminus1.Namespaces
}

// fencingRequired are the nodes that must fence (a watchdog) before
// their replicated-tier pods may move (contract §20.1 "Fencing"): every
// node holding such a pod now and, while HA is off, every non-small node
// of the Hub's records at the primary site, which holds them after ha
// enable (the pinning set of §20.11). The doctor's ha_fencing_unavailable
// (Task 16) uses the same rule.
func fencingRequired(snap nodeadm.Snapshot, place map[string]haPlace, enabled bool, ns nminus1.Namespaces) map[string]bool {
	out := map[string]bool{}
	for i := range snap.Pods {
		if replicatedTier(&snap.Pods[i], ns) {
			out[snap.Pods[i].Node] = true
		}
	}
	if !enabled {
		for id, p := range place {
			if p.site == servers.PrimarySite && p.class != "small" {
				out[id] = true
			}
		}
	}
	return out
}

// snapshotItems are the checklist items judged from the snapshot.
var snapshotItems = []string{"nodes", "servers", "storage", "ingress", "n_minus_1", "watchdog"}

// haChecklistDegraded is the checklist without a snapshot: every
// snapshot item red with why, backup_destination judged (fail closed:
// `ha enable` gates on all ok).
func haChecklistDegraded(why string, backup bool) []HAItem {
	text := fmt.Sprintf(haTextSnapshotF, why)
	out := []HAItem{}
	for _, id := range snapshotItems {
		out = append(out, HAItem{ID: id, Text: text})
	}
	b := HAItem{ID: "backup_destination", OK: backup}
	if !backup {
		b.Text = haTextBackup
	}
	// The contract's order: backup_destination after ingress.
	return slices.Insert(out, 4, b)
}

// haChecklist judges the items of §20.1 over in.
func haChecklist(in haIn) []HAItem {
	snap := in.snap
	var nodes, srv, storage, ingress int
	for _, n := range snap.Nodes {
		p, ok := in.place[n.Name]
		if !ok || !n.Ready {
			continue
		}
		nodes++
		if n.Role == "server" {
			srv++
		}
		if p.storage {
			storage++
		}
		if p.ingress {
			ingress++
		}
	}
	item := func(id string, ok bool, text string) HAItem {
		if ok {
			text = ""
		}
		return HAItem{ID: id, OK: ok, Text: text}
	}
	green := in.n1Err == "" && len(in.n1) > 0
	for _, r := range in.n1 {
		green = green && r.Level == nminus1.Green
	}
	out := []HAItem{
		item("nodes", nodes >= 3, haTextNodes),
		item("servers", srv >= 3, haTextServers),
		item("storage", storage >= 2, haTextStorage),
		item("ingress", ingress >= 1, haTextIngress),
		item("backup_destination", in.backup, haTextBackup),
		item("n_minus_1", green, haTextNMinus1),
	}
	// watchdog: every node that must fence has one (the first by name).
	must := fencingRequired(snap, in.place, in.enabled, in.ns)
	ready := map[string]bool{}
	for _, n := range snap.Nodes {
		ready[n.Name] = n.FencingReady
	}
	wd := HAItem{ID: "watchdog", OK: true}
	for _, name := range slices.Sorted(maps.Keys(must)) {
		if !ready[name] {
			wd = HAItem{ID: "watchdog", Text: fmt.Sprintf(haTextWatchdogF, name)}
			break
		}
	}
	out = append(out, wd)
	if len(in.sites) < 2 {
		return out
	}
	// site_gateway: the mesh refusal for the first site by name without a
	// node whose reach is confirmed (an offered endpoint is planned as
	// reachable but unproven: never a pass; §20.11, verbatim).
	byName := slices.Clone(in.sites)
	sort.Slice(byName, func(i, j int) bool { return byName[i].Name < byName[j].Name })
	gw := HAItem{ID: "site_gateway", OK: true}
	for _, s := range byName {
		if !in.confirmed[s.Name] {
			gw = HAItem{ID: "site_gateway", Text: meshplan.Refusal(s.Name)}
			break
		}
	}
	out = append(out, gw)
	// site_rtt: every healthy server within 100 ms of every other one
	// (the server refusal, verbatim; a missing figure isn't a pass).
	hs := healthyServers(snap, "")
	rt := HAItem{ID: "site_rtt", OK: true}
	for _, s := range hs {
		others := slices.DeleteFunc(slices.Clone(hs), func(o string) bool { return o == s })
		if _, err := servers.CheckRTT("server", others, in.rtt[s]); err != nil {
			rt = HAItem{ID: "site_rtt", Text: err.Error()}
			break
		}
	}
	return append(out, rt)
}

// siteReach: the sites with a planned node whose public endpoint is
// confirmed reachable, and those whose only candidates are offered.
func (h *Hub) siteReach(snap nodeadm.Snapshot) (confirmed map[string]bool, offered []string) {
	in := h.meshInputsOf(snap)
	est, _ := sanitizeEstablished(in)
	confirmed = map[string]bool{}
	off := map[string]bool{}
	for _, n := range est {
		if !n.Public.IsValid() {
			continue
		}
		switch in.reach[n.ID] {
		case state.ReachReachable:
			confirmed[n.Site] = true
		case state.ReachOffered:
			off[n.Site] = true
		}
	}
	for s := range off {
		if !confirmed[s] {
			offered = append(offered, s)
		}
	}
	sort.Strings(offered)
	return confirmed, offered
}

// frontdoorDoc is the part of frontdoor-status' status.json the page
// reads (§20.8; other keys are ignored: the front door owns the shape).
type frontdoorDoc struct {
	V          int        `json:"v"`
	State      string     `json:"state"`
	SnapshotOK *bool      `json:"snapshot_ok"`
	SnapshotAt *time.Time `json:"snapshot_at"`
	Names      map[string]struct {
		Addresses  []string `json:"addresses"`
		WorstCaseS int      `json:"worst_case_s"`
	} `json:"names"`
	Sites map[string]struct {
		Healthy      bool     `json:"healthy"`
		Ingress      []string `json:"ingress"`
		Addresses    []string `json:"addresses"`
		BlindProbers int      `json:"blind_probers"`
	} `json:"sites"`
}

// providerNames are the DNS providers' display names (the dns tool's
// provider ids, §12.2).
var providerNames = map[string]string{
	"cloudflare": "Cloudflare", "porkbun": "Porkbun", "route53": "Route 53",
	"digitalocean": "DigitalOcean", "hetzner": "Hetzner", "hetzner-cloud": "Hetzner Cloud",
}

// ProviderDisplayName is provider id's display name (an unknown id
// itself; none: "your DNS provider").
func ProviderDisplayName(id string) string {
	if n, ok := providerNames[id]; ok {
		return n
	}
	if id == "" || id == "none" {
		return "your DNS provider"
	}
	return id
}

func worstMinutes(worstS int) int { return max(1, worstS/60) }

// worstUnknown: a status without a worst case (none, or not positive)
// is never shown as a short one.
const worstUnknown = "worst case unknown (the front door didn't report it)"

// WorstCaseText is a name's worst case (§20.8): worst_case_s / 60
// floored, at least 1.
func WorstCaseText(worstS int, provider string) string {
	if worstS <= 0 {
		return worstUnknown
	}
	return fmt.Sprintf("worst case ~%d min for clients that hit the dead address first, on %s", worstMinutes(worstS), provider)
}

// SiteWorstCaseText is a site's worst case (§20.8).
func SiteWorstCaseText(site string, worstS int, provider string) string {
	if worstS <= 0 {
		return "if site " + site + " fails: " + worstUnknown
	}
	return fmt.Sprintf("if site %s fails: worst case ~%d min on %s", site, worstMinutes(worstS), provider)
}

// haDNS reads the front door's status: its state and every name with
// its texts (names sorted; sites main first, then by name).
func haDNS(doc []byte, provider string) (HAFrontdoor, []HADNS, error) {
	var d frontdoorDoc
	if err := json.Unmarshal(doc, &d); err != nil {
		return HAFrontdoor{}, nil, errors.New("status.json doesn't decode")
	}
	if d.V != 1 {
		return HAFrontdoor{}, nil, fmt.Errorf("status.json is version %d, not 1", d.V)
	}
	fd := HAFrontdoor{}
	// A status without snapshot_ok can't say its sites are current.
	if d.SnapshotOK == nil || !*d.SnapshotOK {
		fd.SnapshotStale = true
		if d.SnapshotAt != nil {
			fd.SnapshotAt = d.SnapshotAt.UTC().Format(time.RFC3339)
		}
	}
	if d.State == "leading" || d.State == "standing by" {
		fd.State = d.State
	} else {
		fd.Error = "the front door's state is unknown"
	}
	sites := make([]string, 0, len(d.Sites))
	for s := range d.Sites {
		sites = append(sites, s)
	}
	sort.Slice(sites, func(i, j int) bool {
		if (sites[i] == servers.PrimarySite) != (sites[j] == servers.PrimarySite) {
			return sites[i] == servers.PrimarySite
		}
		return sites[i] < sites[j]
	})
	names := make([]string, 0, len(d.Names))
	for n := range d.Names {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]HADNS, 0, len(names))
	for _, n := range names {
		ns := d.Names[n]
		v := HADNS{Name: n, Addresses: slices.Sorted(slices.Values(ns.Addresses)), WorstCaseText: WorstCaseText(ns.WorstCaseS, provider), PerSite: []HADNSSite{}}
		if v.Addresses == nil {
			v.Addresses = []string{}
		}
		for _, s := range sites {
			st := d.Sites[s]
			ps := HADNSSite{Site: s, Healthy: st.Healthy, WorstCaseText: SiteWorstCaseText(s, ns.WorstCaseS, provider),
				Ingress: slices.Sorted(slices.Values(st.Ingress)), Addresses: []string{}, BlindProbers: max(0, st.BlindProbers)}
			if ps.Ingress == nil {
				ps.Ingress = []string{}
			}
			for _, a := range v.Addresses {
				if slices.Contains(st.Addresses, a) {
					ps.Addresses = append(ps.Addresses, a)
				}
			}
			v.PerSite = append(v.PerSite, ps)
		}
		out = append(out, v)
	}
	return fd, out, nil
}

// ProviderID is a DNS provider id as core passes it (^[a-z0-9-]{1,32}$),
// else "" (unknown).
func ProviderID(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || len(v) > 32 || strings.Trim(v, "abcdefghijklmnopqrstuvwxyz0123456789-") != "" {
		return ""
	}
	return v
}

// dnsProvider is the main domain's DNS provider id: HUB_DNS_PROVIDER
// (core's chart, Kubernetes), else core.env's DNS_PROVIDER (Docker, a
// HUB_ENV_VARS key), each checked as an id; "" = unknown (the generic
// text, no note).
func (h *Hub) dnsProvider() string {
	if p := ProviderID(h.cfg.DNSProvider); p != "" {
		return p
	}
	return ProviderID(h.kubeCoreValue("DNS_PROVIDER"))
}

// haView is the page over one refresh's reads. Without a snapshot it
// degrades: every snapshot item red with the reason, the rest answered.
func (h *Hub) haView(r *haRead) *HAView {
	provider := h.dnsProvider()
	v := &HAView{Experimental: true, Enabled: h.cfg.HA, Guarantee: GuaranteeDegraded, Nodes: []HANode{}, Sites: []SiteView{},
		DNS: []HADNS{}, Command: HACommand, Volumes: []nodeadm.Volume{}, Warnings: []string{}, KnownGaps: []string{EnrollKnownGap}}
	if provider == "porkbun" {
		v.CredentialsNote = PorkbunCredentialsNote
	}
	if r.snapErr != nil {
		why := clipRunes(r.snapErr.Error(), 300)
		v.Checklist = haChecklistDegraded(why, h.cfg.BackupDestination)
		v.Warnings = append(v.Warnings, fmt.Sprintf(haTextSnapshotF, why))
	} else {
		h.haSnapshotView(v, r.snap)
	}
	if h.cfg.HA {
		switch {
		case r.statusErr != nil:
			v.Frontdoor.Error = fmt.Sprintf(haTextFrontdoorF, clipRunes(r.statusErr.Error(), 200))
		default:
			fd, dns, err := haDNS(r.status, ProviderDisplayName(provider))
			if err != nil {
				v.Frontdoor.Error = fmt.Sprintf(haTextFrontdoorF, err.Error())
			} else {
				v.Frontdoor, v.DNS = fd, dns
			}
		}
	}
	v.Warnings = append(v.Warnings, h.parkedRevokes()...)
	return v
}

// haSnapshotView fills v from snap: the checklist, guarantee, nodes,
// quorum, sites, volumes and the snapshot's warnings.
func (h *Hub) haSnapshotView(v *HAView, snap nodeadm.Snapshot) {
	ns := h.nminusNamespaces()
	n1, n1Err := h.checkN1(snap)
	place := h.haPlacement(snap)
	sites := h.sitesOf(snap)
	known := map[string]bool{}
	for id := range place {
		known[id] = true
	}
	confirmed, offered := h.siteReach(snap)
	v.Guarantee, v.Quorum = Guarantee(snap.Postgres), snap.Quorum
	if sites != nil {
		v.Sites = sites
	}
	if snap.Volumes != nil {
		v.Volumes = slices.Clone(snap.Volumes)
	}
	v.Checklist = haChecklist(haIn{snap: snap, place: place, n1: n1, n1Err: n1Err, sites: sites, confirmed: confirmed,
		rtt: h.cl.rtt.snapshot(h.now(), known), backup: h.cfg.BackupDestination, enabled: h.cfg.HA, ns: ns})
	level := map[string]nminus1.Level{}
	for _, r := range n1 {
		level[r.Node] = r.Level
	}
	for _, n := range snap.Nodes {
		p := place[n.Name]
		lv, ok := level[n.Name]
		if !ok {
			lv = nminus1.Unknown
		}
		v.Nodes = append(v.Nodes, HANode{Name: n.Name, Role: n.Role, Class: nonEmpty(p.class, n.Labels[nodeadm.LabelClass]), Site: p.site,
			Ready: n.Ready, Fencing: n.FencingReady, NMinus1: lv})
	}
	sort.Slice(v.Nodes, func(i, j int) bool { return v.Nodes[i].Name < v.Nodes[j].Name })
	if len(sites) == 2 {
		v.Warnings = append(v.Warnings, servers.WarnTieBreaker)
	}
	if len(sites) >= 2 {
		for _, s := range offered {
			v.Warnings = append(v.Warnings, fmt.Sprintf(haTextUnconfirmedF, s))
		}
	}
	if n1Err != "" {
		v.Warnings = append(v.Warnings, n1Err)
	}
}

// parkedRevokes: one line per revoked server whose etcd member waits for
// quorum (the revoke's security steps are done; sorted by id).
func (h *Hub) parkedRevokes() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	var out []string
	for id, s := range h.st.Servers {
		if s.ClusterNode() && s.State == ServerRevoked && s.RevokeParked != "" {
			out = append(out, "node "+id+": "+ParkedRevokeText)
		}
	}
	sort.Strings(out)
	return out
}
