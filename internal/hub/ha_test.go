package hub

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/nminus1"
	"github.com/portcullis/hub/internal/nodeadm"
	"github.com/portcullis/hub/internal/state"
)

// haItem is the checklist's item id.
func haItem(t *testing.T, v *HAView, id string) HAItem {
	t.Helper()
	for _, it := range v.Checklist {
		if it.ID == id {
			return it
		}
	}
	t.Fatalf("no checklist item %s in %+v", id, v.Checklist)
	return HAItem{}
}

func haIDs(v *HAView) []string {
	var out []string
	for _, it := range v.Checklist {
		out = append(out, it.ID)
	}
	return out
}

// haLabels marks n storage and ingress (Node labels: a node of init).
func haLabels(n nodeadm.Node, storage, ingress bool) nodeadm.Node {
	if storage {
		n.Labels[nodeadm.LabelStorage] = "true"
	}
	if ingress {
		n.Labels[nodeadm.LabelIngress] = "true"
	}
	n.FencingReady = true
	return n
}

func haFixture(t *testing.T, nodes ...nodeadm.Node) *clusterFixture {
	t.Helper()
	cf := newClusterFixture(t, nodes...)
	cf.h.settleClusterNodes(context.Background()) // pins the nodes of init
	return cf
}

// TestHAChecklistFromSnapshot: the checklist of §20.1 over the snapshot,
// each failing item with its text: 2 nodes; 3 all green but the backup
// destination; a site without a gateway; a server too far; a node with
// core pods but no watchdog; an N−1 refusal is never green.
func TestHAChecklistFromSnapshot(t *testing.T) {
	ctx := context.Background()
	two := haFixture(t,
		haLabels(siteNode("n1", "server", "main", "10.215.0.1", "192.0.2.1", "203.0.113.1"), true, true),
		haLabels(siteNode("n2", "server", "main", "10.215.0.2", "192.0.2.2", ""), true, false))
	v, err := two.h.HA(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !v.Experimental || v.Enabled || v.Command != "./portcullis ha enable" {
		t.Errorf("view %+v", v)
	}
	if got := strings.Join(haIDs(v), ","); got != "nodes,servers,storage,ingress,backup_destination,n_minus_1,watchdog" {
		t.Errorf("one site: items %s", got)
	}
	for id, text := range map[string]string{"nodes": "at least 3 nodes", "servers": "at least 3 servers", "backup_destination": "set an offsite backup destination first"} {
		if it := haItem(t, v, id); it.OK || it.Text != text {
			t.Errorf("%s: %+v, want %q", id, it, text)
		}
	}
	for _, id := range []string{"storage", "ingress", "watchdog"} {
		if it := haItem(t, v, id); !it.OK || it.Text != "" {
			t.Errorf("%s: %+v", id, it)
		}
	}

	// 3 nodes: all green with the destination set (core .env).
	three := haFixture(t,
		haLabels(siteNode("n1", "server", "main", "10.215.0.1", "192.0.2.1", "203.0.113.1"), true, true),
		haLabels(siteNode("n2", "server", "main", "10.215.0.2", "192.0.2.2", ""), true, false),
		haLabels(siteNode("n3", "server", "main", "10.215.0.3", "192.0.2.3", ""), false, false))
	writeFile(t, filepath.Join(three.project, ".env"), "PORTCULLIS_BACKUP_S3_URL=s3://bucket/core\n")
	v, err = three.h.HA(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range v.Checklist {
		if !it.OK {
			t.Errorf("3 nodes: %+v not ok", it)
		}
	}
	// The chart's presence flag counts the same.
	writeFile(t, filepath.Join(three.project, ".env"), "")
	three.h.cfg.BackupDestination = true
	if v, _ = three.h.HA(ctx); !haItem(t, v, "backup_destination").OK {
		t.Error("HUB_BACKUP_DESTINATION=set isn't a destination")
	}
	three.h.cfg.BackupDestination = false

	// A core pod on n3 (no watchdog there): fencing can't be confirmed.
	three.na.mu.Lock()
	three.na.snap.Nodes[2].FencingReady = false
	three.na.snap.Pods = []nodeadm.Pod{{Name: "vault-0", Namespace: "portcullis", Node: "n3", PriorityClass: "portcullis-core"},
		{Name: "traefik-x", Namespace: "portcullis", Node: "n3", PriorityClass: "portcullis-core", DaemonSet: true}}
	three.na.mu.Unlock()
	v, _ = three.h.HA(ctx)
	if it := haItem(t, v, "watchdog"); it.OK || it.Text != "node n3 has no watchdog: fencing can't be confirmed" {
		t.Errorf("watchdog %+v", it)
	}
	// Only a DaemonSet's pod there: no replicated-tier pod, no finding.
	three.na.mu.Lock()
	three.na.snap.Pods = three.na.snap.Pods[1:]
	three.na.mu.Unlock()
	if v, _ = three.h.HA(ctx); !haItem(t, v, "watchdog").OK {
		t.Error("a DaemonSet pod asked for a watchdog")
	}
	// An N−1 refusal (a malformed snapshot): unknown, never green.
	three.na.mu.Lock()
	three.na.snap.Pods = []nodeadm.Pod{{Name: "x", Namespace: "portcullis", Node: "nowhere"}}
	three.na.mu.Unlock()
	v, _ = three.h.HA(ctx)
	if it := haItem(t, v, "n_minus_1"); it.OK || it.Text != "the N−1 check isn't green" {
		t.Errorf("n_minus_1 %+v", it)
	}
	for _, n := range v.Nodes {
		if n.NMinus1 != "unknown" {
			t.Errorf("node %s at %s, want unknown", n.Name, n.NMinus1)
		}
	}

	// Two sites, edge without a reachable node: the mesh refusal; the
	// tie-breaker warning is shown but blocks nothing.
	sites := haFixture(t,
		haLabels(siteNode("n1", "server", "main", "10.215.0.1", "192.0.2.1", "203.0.113.1"), true, true),
		haLabels(siteNode("n2", "server", "main", "10.215.0.2", "192.0.2.2", ""), true, false),
		haLabels(siteNode("n3", "server", "main", "10.215.0.3", "192.0.2.3", ""), false, false),
		haLabels(siteNode("e1", "agent", "edge", "10.215.0.5", "198.18.0.5", ""), false, false))
	// No figures: any collection the settle started is done, then dropped.
	for sites.h.cl.rtt.busy.Load() {
		time.Sleep(time.Millisecond)
	}
	sites.h.cl.rtt.mu.Lock()
	sites.h.cl.rtt.v, sites.h.cl.rtt.at = nil, nil
	sites.h.cl.rtt.mu.Unlock()
	v, err = sites.h.HA(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(haIDs(v), ","); !strings.HasSuffix(got, ",watchdog,site_gateway,site_rtt") {
		t.Errorf("two sites: items %s", got)
	}
	if it := haItem(t, v, "site_gateway"); it.OK || it.Text != "site edge needs one node reachable on UDP 51830 first (a cloud node, or one forwarded port)" {
		t.Errorf("site_gateway %+v", it)
	}
	// No round trips measured yet: not a pass.
	if it := haItem(t, v, "site_rtt"); it.OK || !strings.HasPrefix(it.Text, "no mesh answer from ") {
		t.Errorf("site_rtt unmeasured %+v", it)
	}
	if len(v.Warnings) != 1 || v.Warnings[0] != "Only main can survive on its own: add a tie-breaker at a third location (a small cloud VM or a Pi elsewhere)." {
		t.Errorf("warnings %q", v.Warnings)
	}
	// A server 120 ms from another: the server refusal, verbatim.
	sites.na.setRTT(map[string]map[string]int{"n1": {"n2": 2, "n3": 120}, "n2": {"n1": 2, "n3": 3}, "n3": {"n1": 120, "n2": 3}, "e1": {}})
	snap, _ := sites.na.Cluster(ctx)
	sites.h.collectRTT(ctx, snap, sites.h.now())
	v, _ = sites.h.HA(ctx)
	if it := haItem(t, v, "site_rtt"); it.OK || it.Text != "too far for one cluster: 120 ms (servers need 100 ms or less)" {
		t.Errorf("site_rtt %+v", it)
	}
	sites.na.setRTT(map[string]map[string]int{"n1": {"n2": 2, "n3": 20}, "n2": {"n1": 2, "n3": 3}, "n3": {"n1": 20, "n2": 3}, "e1": {}})
	snap, _ = sites.na.Cluster(ctx)
	sites.h.collectRTT(ctx, snap, sites.h.now())
	if v, _ = sites.h.HA(ctx); !haItem(t, v, "site_rtt").OK {
		t.Errorf("site_rtt within the limit %+v", haItem(t, v, "site_rtt"))
	}
}

// TestHAChecklistNMinus1Yellow: only an all-green N−1 result is green:
// yellow (degraded) isn't, nor no result at all.
func TestHAChecklistNMinus1Yellow(t *testing.T) {
	snap := nodeadm.Snapshot{Nodes: []nodeadm.Node{{Name: "n1", Ready: true}}}
	for _, n1 := range [][]nminus1.Result{{{Node: "n1", Level: nminus1.Yellow}}, nil} {
		items := haChecklist(snap, map[string]haPlace{}, n1, "", nil, nil, false, nminus1.DefaultNamespaces)
		for _, it := range items {
			if it.ID == "n_minus_1" && (it.OK || it.Text != "the N−1 check isn't green") {
				t.Errorf("%v: %+v", n1, it)
			}
		}
	}
	items := haChecklist(snap, map[string]haPlace{}, []nminus1.Result{{Node: "n1", Level: nminus1.Green}}, "", nil, nil, false, nminus1.DefaultNamespaces)
	if items[5].ID != "n_minus_1" || !items[5].OK {
		t.Errorf("green: %+v", items[5])
	}
}

// TestGuaranteeText: zero loss only with a synchronous standby.
func TestGuaranteeText(t *testing.T) {
	for _, c := range []struct {
		pg   nodeadm.Postgres
		want string
	}{
		{nodeadm.Postgres{Instances: 2, SyncStandbys: 1}, "Zero loss on one failure"},
		{nodeadm.Postgres{Instances: 3, SyncStandbys: 1}, "Zero loss on one failure"},
		{nodeadm.Postgres{Instances: 2, SyncStandbys: 0}, "Degraded: one more failure may lose the last writes"},
		{nodeadm.Postgres{Instances: 1, SyncStandbys: 0}, "Degraded: one more failure may lose the last writes"},
		{nodeadm.Postgres{Instances: 1, SyncStandbys: 1}, "Degraded: one more failure may lose the last writes"},
	} {
		if got := Guarantee(c.pg); got != c.want {
			t.Errorf("%+v: %q, want %q", c.pg, got, c.want)
		}
	}
	cf := haFixture(t, haLabels(siteNode("n1", "server", "main", "10.215.0.1", "192.0.2.1", ""), true, true))
	cf.na.mu.Lock()
	cf.na.snap.Postgres = nodeadm.Postgres{Instances: 2, SyncStandbys: 1}
	cf.na.mu.Unlock()
	if v, err := cf.h.HA(context.Background()); err != nil || v.Guarantee != GuaranteeZeroLoss {
		t.Errorf("page guarantee %v %v", v, err)
	}
}

// frontdoorVector is the part of a frontdoor_vectors.json case the
// worst-case texts need.
type frontdoorVector struct {
	Name                  string            `json:"name"`
	Provider              string            `json:"provider"`
	ProviderName          string            `json:"provider_name"`
	ProviderMinTTL        int               `json:"provider_min_ttl"`
	Names                 []string          `json:"names"`
	WantWorstCaseText     map[string]string `json:"want_worst_case_text"`
	WantSiteWorstCaseText map[string]string `json:"want_site_worst_case_text"`
}

// TestWorstCaseTextVectors: the page's texts are the vectors'
// want_worst_case_text and want_site_worst_case_text (pre-flight P5),
// rendered from a frontdoor-status the front door would write
// (worst_case_s = 30 s + the TTL, the TTL max(60 s, the provider's
// minimum)), with the Hub's display name of the provider; Porkbun reads
// "~10 min".
func TestWorstCaseTextVectors(t *testing.T) {
	b, err := os.ReadFile("testdata/frontdoor_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []frontdoorVector
	if err := json.Unmarshal(b, &vs); err != nil {
		t.Fatal(err)
	}
	n, porkbun := 0, false
	for _, v := range vs {
		if v.WantWorstCaseText == nil {
			continue
		}
		n++
		if got := ProviderDisplayName(v.Provider); got != v.ProviderName {
			t.Errorf("%s: provider %s shown as %q, want %q", v.Name, v.Provider, got, v.ProviderName)
		}
		ws := 30 + max(60, v.ProviderMinTTL)
		doc := map[string]any{"v": 1, "state": "leading", "names": map[string]any{}, "sites": map[string]any{}, "probes": map[string]any{}}
		for name := range v.WantWorstCaseText {
			doc["names"].(map[string]any)[name] = map[string]any{"addresses": []string{"198.51.100.7"}, "ttl": ws - 30, "worst_case_s": ws, "last_change": nil, "pending": nil}
		}
		for site := range v.WantSiteWorstCaseText {
			doc["sites"].(map[string]any)[site] = map[string]any{"healthy": true, "ingress": []string{}}
		}
		raw, _ := json.Marshal(doc)
		fd, dns, err := haDNS(raw, ProviderDisplayName(v.Provider))
		if err != nil || fd.State != "leading" || len(dns) != len(v.WantWorstCaseText) {
			t.Fatalf("%s: %+v %+v %v", v.Name, fd, dns, err)
		}
		for _, d := range dns {
			if d.WorstCaseText != v.WantWorstCaseText[d.Name] {
				t.Errorf("%s: %s: %q, want %q", v.Name, d.Name, d.WorstCaseText, v.WantWorstCaseText[d.Name])
			}
			if len(d.PerSite) != len(v.WantSiteWorstCaseText) || d.PerSite[0].Site != "main" {
				t.Errorf("%s: per_site %+v", v.Name, d.PerSite)
			}
			for _, s := range d.PerSite {
				if s.WorstCaseText != v.WantSiteWorstCaseText[s.Site] {
					t.Errorf("%s: site %s: %q, want %q", v.Name, s.Site, s.WorstCaseText, v.WantSiteWorstCaseText[s.Site])
				}
			}
		}
		porkbun = porkbun || strings.Contains(v.WantWorstCaseText["example.org"], "~10 min") && v.ProviderName == "Porkbun"
	}
	if n < 2 || !porkbun {
		t.Errorf("%d vectors with texts, Porkbun ~10 min %v", n, porkbun)
	}
	// Floored, at least 1.
	if WorstCaseText(59, "X") != "worst case ~1 min for clients that hit the dead address first, on X" || SiteWorstCaseText("edge", 179, "X") != "if site edge fails: worst case ~2 min on X" {
		t.Error("minutes aren't floored to at least 1")
	}
	// A document of another version, or a state nobody writes.
	if _, _, err := haDNS([]byte(`{"v":2}`), "X"); err == nil {
		t.Error("version 2 accepted")
	}
	if fd, _, err := haDNS([]byte(`{"v":1,"state":"<b>"}`), "X"); err != nil || fd.State != "" || fd.Error == "" {
		t.Errorf("odd state: %+v %v", fd, err)
	}
}

// TestHAPageNeverShowsCredentials: the page names no key or value of the
// front door's credentials (frontdoor-env: it never reads them) nor of
// the backup destination (presence only, its URL never shown), and on
// Porkbun says the keys are account-wide.
func TestHAPageNeverShowsCredentials(t *testing.T) {
	cf := haFixture(t,
		haLabels(siteNode("n1", "server", "main", "10.215.0.1", "192.0.2.1", "203.0.113.1"), true, true),
		haLabels(siteNode("n2", "server", "main", "10.215.0.2", "192.0.2.2", ""), true, false),
		haLabels(siteNode("n3", "server", "main", "10.215.0.3", "192.0.2.3", ""), false, false))
	cf.h.cfg.HA = true
	secrets := []string{"pk1_SECRETporkbunkey", "sk1_SECRETporkbunsecret", "AKIASECRETBACKUPKEY", "SECRETbackupPassword", "secret-bucket-name", "PORKBUN_API_KEY", "AWS_SECRET_ACCESS_KEY", "credentials.json"}
	writeFile(t, filepath.Join(cf.project, ".env"), "DNS_PROVIDER=porkbun\nPORKBUN_API_KEY=pk1_SECRETporkbunkey\nPORKBUN_SECRET_API_KEY=sk1_SECRETporkbunsecret\n"+
		"PORTCULLIS_BACKUP_S3_URL=s3://AKIASECRETBACKUPKEY:SECRETbackupPassword@s3.example.org/secret-bucket-name\n")
	writeFile(t, filepath.Join(cf.project, "secrets", "backup-destination.env"), "AWS_ACCESS_KEY_ID=AKIASECRETBACKUPKEY\nAWS_SECRET_ACCESS_KEY=SECRETbackupPassword\n")
	// frontdoor-env's credentials.json holds the PORKBUN_* values above:
	// the Hub's reader is only ever asked for frontdoor-status.
	var mu sync.Mutex
	reads := 0
	cf.h.SetFrontdoorStatus(func(context.Context) ([]byte, error) {
		mu.Lock()
		reads++
		mu.Unlock()
		return []byte(`{"v":1,"state":"standing by","names":{"example.org":{"addresses":["198.51.100.7"],"ttl":600,"worst_case_s":630,"last_change":null,"pending":null}},` +
			`"probes":{"n1":{"ok":true,"verdict":"healthy","internal_only":true,"blind":false}},"sites":{"main":{"healthy":true,"ingress":["n1"]}}}`), nil
	})
	v, err := cf.h.HA(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(v)
	for _, s := range secrets {
		if strings.Contains(string(b), s) {
			t.Errorf("the page shows %q: %s", s, b)
		}
	}
	if v.CredentialsNote != "Porkbun API keys can change every domain in the account: Portcullis can't narrow them" {
		t.Errorf("credentials_note %q", v.CredentialsNote)
	}
	if !haItem(t, v, "backup_destination").OK || reads != 1 {
		t.Errorf("destination %+v, %d status reads", haItem(t, v, "backup_destination"), reads)
	}
	want := `[{"name":"example.org","addresses":["198.51.100.7"],"worst_case_text":"worst case ~10 min for clients that hit the dead address first, on Porkbun",` +
		`"per_site":[{"site":"main","healthy":true,"worst_case_text":"if site main fails: worst case ~10 min on Porkbun"}]}]`
	if d, _ := json.Marshal(v.DNS); string(d) != want || v.Frontdoor.State != "standing by" {
		t.Errorf("dns %s, front door %+v", d, v.Frontdoor)
	}
	if !v.Enabled || len(v.KnownGaps) != 1 || !strings.Contains(v.KnownGaps[0], "enrol") {
		t.Errorf("enabled %v, known gaps %q", v.Enabled, v.KnownGaps)
	}

	// An unreadable status: the error (clipped), no names.
	cf.h.SetFrontdoorStatus(func(context.Context) ([]byte, error) {
		return nil, errors.New("configmaps \"frontdoor-status\" not found")
	})
	if v, _ = cf.h.HA(context.Background()); len(v.DNS) != 0 || !strings.HasPrefix(v.Frontdoor.Error, "the front door's status isn't readable: ") {
		t.Errorf("unreadable: %+v %+v", v.DNS, v.Frontdoor)
	}
	// Without HA the front door doesn't run: not read.
	cf.h.cfg.HA = false
	reads = 0
	if v, _ = cf.h.HA(context.Background()); reads != 0 || v.Frontdoor != (HAFrontdoor{}) {
		t.Errorf("read without HA: %d, %+v", reads, v.Frontdoor)
	}
}

// TestHAParkedRevokeShown: a parked revoke says it waits for quorum.
func TestHAParkedRevokeShown(t *testing.T) {
	cf := haFixture(t, haLabels(siteNode("n1", "server", "main", "10.215.0.1", "192.0.2.1", ""), true, true))
	cf.h.mu.Lock()
	if cf.h.st.Servers == nil {
		cf.h.st.Servers = map[string]state.Server{}
	}
	cf.h.st.Servers["gone"] = state.Server{Kind: state.KindClusterNode, State: ServerRevoked, RevokeParked: "quorum_minimum"}
	cf.h.mu.Unlock()
	v, err := cf.h.HA(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Warnings) != 1 || v.Warnings[0] != "node gone: revoked; waiting for quorum to remove its etcd member" {
		t.Errorf("warnings %q", v.Warnings)
	}
}

// TestHAOffKubernetes: Docker and Podman: 409, nothing read.
func TestHAOffKubernetes(t *testing.T) {
	f := newFixture(t)
	_, err := f.h.HA(context.Background())
	var se *StatusError
	if !errors.As(err, &se) || se.Status != 409 || se.Error() != "high availability needs Kubernetes" {
		t.Errorf("off Kubernetes: %v", err)
	}
}
