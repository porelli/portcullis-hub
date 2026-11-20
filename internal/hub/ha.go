package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/portcullis/hub/internal/meshplan"
	"github.com/portcullis/hub/internal/nminus1"
	"github.com/portcullis/hub/internal/nodeadm"
	"github.com/portcullis/hub/internal/servers"
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
// destination is presence only (PORTCULLIS_BACKUP_S3_URL set in core's
// .env, or HUB_BACKUP_DESTINATION=set from the chart, pre-flight P43).

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

// The core.env keys the page reads (presence or a provider id only).
const (
	VarBackupS3URL = "PORTCULLIS_BACKUP_S3_URL"
	VarDNSProvider = "DNS_PROVIDER"
)

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
// ok, and the worst case if it fails.
type HADNSSite struct {
	Site          string `json:"site"`
	Healthy       bool   `json:"healthy"`
	WorstCaseText string `json:"worst_case_text"`
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
	status    []byte
	statusErr error
}

// HA is GET /api/ha: a fresh snapshot (shared by concurrent refreshes),
// judged now. Read-only.
func (h *Hub) HA(ctx context.Context) (*HAView, error) {
	if err := h.HAOn(); err != nil {
		return nil, err
	}
	ch := h.ha.reads.DoChan(opKeyHA, func() (any, error) {
		// The shared read outlives one caller's cancel (another may wait
		// on it), never haReadWait.
		c, cancel := context.WithTimeout(context.WithoutCancel(ctx), haReadWait)
		defer cancel()
		api, err := h.nodeadmAPI(c)
		if err != nil {
			return nil, err
		}
		snap, err := h.clusterSnapshot(c, api)
		if err != nil {
			return nil, nodeadmErr(err)
		}
		r := &haRead{snap: snap}
		if h.cfg.HA {
			r.status, r.statusErr = h.readFrontdoorStatus(c)
		}
		return r, nil
	})
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-ch:
		if res.Err != nil {
			return nil, res.Err
		}
		r := res.Val.(*haRead)
		return h.haView(r.snap, r.status, r.statusErr), nil
	}
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

// haChecklist judges the items of §20.1 over snap (place: the Hub's
// placement; n1: the N−1 results, n1Err the check's refusal; sites the
// sites view; rtt the round trips; backup the destination's presence).
func haChecklist(snap nodeadm.Snapshot, place map[string]haPlace, n1 []nminus1.Result, n1Err string, sites []SiteView, rtt map[string]map[string]int, backup bool, ns nminus1.Namespaces) []HAItem {
	var nodes, srv, storage, ingress int
	for _, n := range snap.Nodes {
		p, ok := place[n.Name]
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
	green := n1Err == "" && len(n1) > 0
	for _, r := range n1 {
		green = green && r.Level == nminus1.Green
	}
	out := []HAItem{
		item("nodes", nodes >= 3, haTextNodes),
		item("servers", srv >= 3, haTextServers),
		item("storage", storage >= 2, haTextStorage),
		item("ingress", ingress >= 1, haTextIngress),
		item("backup_destination", backup, haTextBackup),
		item("n_minus_1", green, haTextNMinus1),
	}
	// watchdog: every node holding replicated-tier pods fences (by name).
	holds := map[string]bool{}
	for i := range snap.Pods {
		if replicatedTier(&snap.Pods[i], ns) {
			holds[snap.Pods[i].Node] = true
		}
	}
	wd := HAItem{ID: "watchdog", OK: true}
	names := make([]string, 0, len(snap.Nodes))
	for _, n := range snap.Nodes {
		names = append(names, n.Name)
	}
	sort.Strings(names)
	for _, name := range names {
		if n := snap.Node(name); holds[name] && !n.FencingReady {
			wd = HAItem{ID: "watchdog", Text: fmt.Sprintf(haTextWatchdogF, name)}
			break
		}
	}
	out = append(out, wd)
	if len(sites) < 2 {
		return out
	}
	// site_gateway: the mesh refusal for the first site by name without a
	// reachable node (§20.11, verbatim).
	byName := slices.Clone(sites)
	sort.Slice(byName, func(i, j int) bool { return byName[i].Name < byName[j].Name })
	gw := HAItem{ID: "site_gateway", OK: true}
	for _, s := range byName {
		if s.Gateway == "" {
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
		if _, err := servers.CheckRTT("server", others, rtt[s]); err != nil {
			rt = HAItem{ID: "site_rtt", Text: err.Error()}
			break
		}
	}
	return append(out, rt)
}

// frontdoorDoc is the part of frontdoor-status' status.json the page
// reads (§20.8; other keys are ignored: the front door owns the shape).
type frontdoorDoc struct {
	V     int    `json:"v"`
	State string `json:"state"`
	Names map[string]struct {
		Addresses  []string `json:"addresses"`
		WorstCaseS int      `json:"worst_case_s"`
	} `json:"names"`
	Sites map[string]struct {
		Healthy bool `json:"healthy"`
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

// WorstCaseText is a name's worst case (§20.8): worst_case_s / 60
// floored, at least 1.
func WorstCaseText(worstS int, provider string) string {
	return fmt.Sprintf("worst case ~%d min for clients that hit the dead address first, on %s", worstMinutes(worstS), provider)
}

// SiteWorstCaseText is a site's worst case (§20.8).
func SiteWorstCaseText(site string, worstS int, provider string) string {
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
			v.PerSite = append(v.PerSite, HADNSSite{Site: s, Healthy: d.Sites[s].Healthy, WorstCaseText: SiteWorstCaseText(s, ns.WorstCaseS, provider)})
		}
		out = append(out, v)
	}
	return fd, out, nil
}

// backupDestinationSet: the offsite destination is configured (presence
// only: the Hub never reads its credentials).
func (h *Hub) backupDestinationSet() bool {
	return h.kubeCoreValue(VarBackupS3URL) != "" || h.cfg.BackupDestination
}

// haView is the page over one refresh's reads.
func (h *Hub) haView(snap nodeadm.Snapshot, status []byte, statusErr error) *HAView {
	ns := h.nminusNamespaces()
	n1, n1Err := h.checkN1(snap)
	place := h.haPlacement(snap)
	sites := h.sitesOf(snap)
	known := map[string]bool{}
	for id := range place {
		known[id] = true
	}
	rtt := h.cl.rtt.snapshot(h.now(), known)
	provider := h.kubeCoreValue(VarDNSProvider)
	v := &HAView{Experimental: true, Enabled: h.cfg.HA, Guarantee: Guarantee(snap.Postgres), Quorum: snap.Quorum, Sites: sites,
		DNS: []HADNS{}, Command: HACommand, Volumes: slices.Clone(snap.Volumes), Warnings: []string{}, KnownGaps: []string{EnrollKnownGap}}
	if v.Sites == nil {
		v.Sites = []SiteView{}
	}
	if v.Volumes == nil {
		v.Volumes = []nodeadm.Volume{}
	}
	v.Checklist = haChecklist(snap, place, n1, n1Err, sites, rtt, h.backupDestinationSet(), ns)
	level := map[string]nminus1.Level{}
	for _, r := range n1 {
		level[r.Node] = r.Level
	}
	v.Nodes = []HANode{}
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
	if provider == "porkbun" {
		v.CredentialsNote = PorkbunCredentialsNote
	}
	if h.cfg.HA {
		switch {
		case statusErr != nil:
			v.Frontdoor.Error = fmt.Sprintf(haTextFrontdoorF, clipRunes(statusErr.Error(), 200))
		default:
			fd, dns, err := haDNS(status, ProviderDisplayName(provider))
			if err != nil {
				v.Frontdoor.Error = fmt.Sprintf(haTextFrontdoorF, err.Error())
			} else {
				v.Frontdoor, v.DNS = fd, dns
			}
		}
	}
	if len(sites) == 2 {
		v.Warnings = append(v.Warnings, servers.WarnTieBreaker)
	}
	if n1Err != "" {
		v.Warnings = append(v.Warnings, n1Err)
	}
	v.Warnings = append(v.Warnings, h.parkedRevokes()...)
	return v
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
