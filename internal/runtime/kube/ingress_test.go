package kube

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

	ktypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	k8stesting "k8s.io/client-go/testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"
)

func ingressYAML(t *testing.T, objs []*unstructured.Unstructured) string {
	var b strings.Builder
	for _, o := range objs {
		j, _ := json.Marshal(o.Object)
		y, _ := yaml.JSONToYAML(j)
		b.WriteString("---\n")
		b.Write(y)
	}
	return b.String()
}

// The routers the Hub renders, by shape.
var ingressCases = map[string]map[string]map[string]string{
	"forward-auth": {"web": {
		"traefik.enable":                                     "true",
		"traefik.http.routers.app.rule":                      "Host(`app.example.org`)",
		"traefik.http.routers.app.entrypoints":               "websecure",
		"traefik.http.routers.app.tls.options":               "authaware@file",
		"traefik.http.routers.app.middlewares":               "client-headers@file,portcullis-auth@docker,portcullis-groups@docker,security-headers@file",
		"traefik.http.services.app.loadbalancer.server.port": "8080",
	}},
	"oauth2": {"web": {
		"traefik.http.routers.app-oauth.rule":        "Host(`app.example.org`) && PathPrefix(`/oauth2/`)",
		"traefik.http.routers.app-oauth.priority":    "100",
		"traefik.http.routers.app-oauth.service":     "forward-auth-ext@docker",
		"traefik.http.routers.app-oauth.tls.options": "authaware@file",
	}},
	"public-link": {"web": {
		"traefik.http.routers.app-pub.rule":        "Host(`app.example.org`) && PathPrefix(`/s/`)",
		"traefik.http.routers.app-pub.middlewares": "portcullis-public-guard@docker,portcullis-public-strip-app,security-headers@file",
		"traefik.http.routers.app-pub.tls.options": "public@file",
		"traefik.http.routers.app-pub.service":     "app",
		"traefik.http.middlewares.portcullis-public-strip-app.headers.customrequestheaders.X-Forwarded-User": "",
		"traefik.http.middlewares.portcullis-public-strip-app.headers.customrequestheaders.X_Forwarded_User": "",
		"traefik.http.services.app.loadbalancer.server.port":                                                 "8080",
	}},
	"mcp": {"companion": {
		"traefik.http.routers.app-mcp.rule":        "Host(`mcp.example.org`) && PathPrefix(`/app/`)",
		"traefik.http.routers.app-mcp.service":     "mcp-gate@docker",
		"traefik.http.routers.app-mcp.tls.options": "protected-any@file",
	}},
	"extra-domain": {"web": {
		"traefik.http.routers.app.rule":                      "Host(`app.team-b.example.net`)",
		"traefik.http.routers.app.middlewares":               "portcullis-auth-ext@docker,portcullis-groups@docker",
		"traefik.http.routers.app.tls.options":               "authaware@file",
		"traefik.http.services.app.loadbalancer.server.port": "80",
	}},
	"vpn-only": {"web": {
		"traefik.http.routers.app.rule":                                                 "Host(`app.example.org`)",
		"traefik.http.routers.app.entrypoints":                                          "vpnsecure",
		"traefik.http.routers.app.middlewares":                                          "portcullis-vpnallow-app,client-headers@file,portcullis-auth@docker,portcullis-groups-vpn@docker",
		"traefik.http.routers.app.tls.options":                                          "authaware@file",
		"traefik.http.middlewares.portcullis-vpnallow-app.ipallowlist.sourcerange":      "100.64.0.0/10,10.213.0.0/22",
		"traefik.http.middlewares.portcullis-vpnallow-app.ipallowlist.rejectstatuscode": "404",
		"traefik.http.routers.app-vpnreq.rule":                                          "Host(`app.example.org`)",
		"traefik.http.routers.app-vpnreq.service":                                       "group-gate@docker",
		"traefik.http.routers.app-vpnreq.middlewares":                                   "vpn-required-path@docker",
		"traefik.http.services.app.loadbalancer.server.port":                            "80",
	}},
}

func TestIngressGoldens(t *testing.T) {
	for name, labels := range ingressCases {
		objs, err := IngressObjects("app", EdgeNamespace, ns, labels)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		got := ingressYAML(t, objs)
		p := filepath.Join("testdata", "ingress", name+".yaml")
		if *update {
			os.WriteFile(p, []byte(got), 0o644)
			continue
		}
		want, _ := os.ReadFile(p)
		if string(want) != got {
			t.Errorf("%s differs (-update):\n%s", name, got)
		}
	}
	// vpnsecure: the allowlist is the chain's first middleware, in the
	// instance's own namespace.
	objs, _ := IngressObjects("app", EdgeNamespace, ns, ingressCases["vpn-only"])
	for _, o := range objs {
		if o.GetKind() == "IngressRoute" && o.GetName() == "app--r-app" {
			r := o.Object["spec"].(map[string]any)["routes"].([]any)[0].(map[string]any)
			m := r["middlewares"].([]any)[0].(map[string]any)
			if m["name"] != "app--m-portcullis-vpnallow-app" || m["namespace"] != EdgeNamespace {
				t.Errorf("first middleware %v", m)
			}
		}
	}
}

func refusedErr(err error) string {
	var r *ErrRefused
	if errors.As(err, &r) {
		return r.Reason
	}
	return ""
}

func TestCrossNamespaceMiddlewareRefused(t *testing.T) {
	for _, mw := range []string{"hub-proxy-secret@docker", "portcullis-auth-console@docker", "other-app-mw@docker", "strip-forwarded@file", "api@internal", "x@kubernetescrd"} {
		_, err := IngressObjects("app", EdgeNamespace, ns, map[string]map[string]string{"web": {
			"traefik.http.routers.app.rule": "Host(`a.example.org`)", "traefik.http.routers.app.middlewares": mw,
			"traefik.http.services.app.loadbalancer.server.port": "80"}})
		if refusedErr(err) == "" {
			t.Errorf("%s: %v", mw, err)
		}
	}
}

func TestForwardAuthMiddlewareRefused(t *testing.T) {
	for _, f := range []map[string]string{
		{"traefik.http.middlewares.fa.forwardauth.address": "http://group-gate.portcullis.svc:8080"},
		{"traefik.http.middlewares.fa.headers.customrequestheaders.X-Portcullis-Proxy-Secret": "guess"},
		{"traefik.http.middlewares.fa.headers.customrequestheaders.X_Portcullis_User": "root"},
	} {
		f["traefik.http.routers.app.rule"] = "Host(`a.example.org`)"
		f["traefik.http.services.app.loadbalancer.server.port"] = "80"
		if _, err := IngressObjects("app", EdgeNamespace, ns, map[string]map[string]string{"web": f}); refusedErr(err) == "" {
			t.Errorf("%v: %v", f, err)
		}
	}
}

func TestCoreServiceRefsAreFile(t *testing.T) {
	for svc, want := range map[string]string{"forward-auth-ext@docker": "forward-auth-ext@file", "mcp-gate@docker": "mcp-gate@file", "group-gate@docker": "group-gate@file"} {
		objs, err := IngressObjects("app", EdgeNamespace, ns, map[string]map[string]string{"web": {"traefik.http.routers.r.rule": "Host(`a.example.org`)", "traefik.http.routers.r.service": svc}})
		if err != nil {
			t.Fatalf("%s: %v", svc, err)
		}
		r := objs[0].Object["spec"].(map[string]any)["routes"].([]any)[0].(map[string]any)
		s := r["services"].([]any)[0].(map[string]any)
		if s["name"] != want || s["kind"] != "TraefikService" {
			t.Errorf("%s → %v", svc, s)
		}
	}
	for _, svc := range []string{"hub@docker", "api@internal", "keycloak@docker", "noop@internal"} {
		_, err := IngressObjects("app", EdgeNamespace, ns, map[string]map[string]string{"web": {"traefik.http.routers.r.rule": "Host(`a.example.org`)", "traefik.http.routers.r.service": svc}})
		if refusedErr(err) == "" {
			t.Errorf("%s accepted: %v", svc, err)
		}
	}
}

func policyByName(t *testing.T, objs []*unstructured.Unstructured, name string) map[string]any {
	for _, o := range objs {
		if o.GetName() == name {
			return o.Object["spec"].(map[string]any)
		}
	}
	t.Fatalf("no policy %s", name)
	return nil
}

func TestPolicyRoutedPortTraefikOnly(t *testing.T) {
	objs, err := InstancePolicies(PolicyInput{Instance: "app", Namespace: ns, RoutedPorts: map[string][]int{"web": {8080}}, CompanionPorts: map[string][]int{"tok": {9000}},
		Networks: map[string][]string{"default": {"web", "tok"}}, Settings: Settings{PodCIDR: "10.42.0.0/16", ServiceCIDR: "10.43.0.0/16"}})
	if err != nil {
		t.Fatal(err)
	}
	for name, comp := range map[string]string{"app--routed-web": "traefik", "app--companion-tok": "mcp-gate"} {
		spec := policyByName(t, objs, name)
		ing := spec["ingress"].([]any)
		if len(ing) != 1 {
			t.Fatalf("%s ingress %v", name, ing)
		}
		from := ing[0].(map[string]any)["from"].([]any)
		peer := from[0].(map[string]any)
		ns := peer["namespaceSelector"].(map[string]any)["matchLabels"].(map[string]any)
		pod := peer["podSelector"].(map[string]any)["matchLabels"].(map[string]any)
		if len(from) != 1 || ns[nsLabel] != "portcullis" || pod[LabelComponent] != comp || len(pod) != 1 {
			t.Errorf("%s from %v", name, from)
		}
		sel := spec["podSelector"].(map[string]any)["matchLabels"].(map[string]any)
		if sel[LabelInstance] != "app" || len(sel) != 2 {
			t.Errorf("%s selector %v", name, sel)
		}
	}
	// Never an empty selector or a rule without peers.
	for _, o := range objs {
		b, _ := json.Marshal(o.Object)
		if strings.Contains(string(b), `"podSelector":{}`) || strings.Contains(string(b), `"namespaceSelector":{}`) || strings.Contains(string(b), `"from":null`) {
			t.Errorf("%s: an open shape: %s", o.GetName(), b)
		}
		for _, k := range []string{"ingress", "egress"} {
			rules, _ := o.Object["spec"].(map[string]any)[k].([]any)
			for _, r := range rules {
				m := r.(map[string]any)
				if m["from"] == nil && m["to"] == nil {
					t.Errorf("%s: a %s rule without peers", o.GetName(), k)
				}
			}
		}
	}
}

func TestPolicyEgressExcludesClusterAndNode(t *testing.T) {
	in := PolicyInput{Instance: "app", Namespace: ns, Networks: map[string][]string{"default": {"web"}}, Egress: []string{"web"},
		Settings: Settings{PodCIDR: "10.42.0.0/16", ServiceCIDR: "10.43.0.0/16", NodeAddresses: []string{"192.0.2.10", "192.0.2.11"}}}
	objs, err := InstancePolicies(in)
	if err != nil {
		t.Fatal(err)
	}
	spec := policyByName(t, objs, "app--egress")
	eg := spec["egress"].([]any)
	ip := eg[0].(map[string]any)["to"].([]any)[0].(map[string]any)["ipBlock"].(map[string]any)
	ex := ip["except"].([]any)
	for _, want := range []string{"10.42.0.0/16", "10.43.0.0/16", "169.254.0.0/16", "192.0.2.10/32", "192.0.2.11/32"} {
		found := false
		for _, e := range ex {
			found = found || e == want
		}
		if !found {
			t.Errorf("except lacks %s: %v", want, ex)
		}
	}
	if ip["cidr"] != "0.0.0.0/0" {
		t.Errorf("cidr %v", ip["cidr"])
	}
	nodes := eg[1].(map[string]any)
	if len(nodes["ports"].([]any)) != 2 || len(nodes["to"].([]any)) != 2 {
		t.Errorf("node rule %v", nodes)
	}
	// No node addresses: refused, nothing deployed.
	in.Settings.NodeAddresses = nil
	if _, err := InstancePolicies(in); refusedErr(err) == "" {
		t.Errorf("no node addresses: %v", err)
	}
	// A VPN gateway: egress to wg on its edge port only.
	slot := 3
	in.Settings.NodeAddresses, in.VPNSlot = []string{"192.0.2.10"}, &slot
	objs, _ = InstancePolicies(in)
	spec = policyByName(t, objs, "app--vpn-edge")
	r := spec["egress"].([]any)[0].(map[string]any)
	if p := r["ports"].([]any)[0].(map[string]any)["port"]; p != int64(9004) {
		t.Errorf("edge port %v", p)
	}
	if spec["podSelector"].(map[string]any)["matchLabels"].(map[string]any)[LabelVPNSlot] != "3" {
		t.Errorf("selector %v", spec["podSelector"])
	}
}

func readyPod(name, uid, inst, ip string, ready bool) *corev1.Pod {
	st := corev1.ConditionFalse
	if ready {
		st = corev1.ConditionTrue
	}
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, UID: ktypes.UID(uid), Namespace: ns, Labels: map[string]string{LabelInstance: inst, LabelVPNSlot: "3"}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: ip, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: st}}}}
}

// gwRecorder collects WatchGateways' callbacks.
type gwRecorder struct {
	mu   sync.Mutex
	last map[string]GatewayPod
	n    int
}

func (r *gwRecorder) fn(m map[string]GatewayPod) {
	r.mu.Lock()
	r.last, r.n = m, r.n+1
	r.mu.Unlock()
}

func (r *gwRecorder) waitFor(t *testing.T, what string, ok func(map[string]GatewayPod) bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		r.mu.Lock()
		m, n := r.last, r.n
		r.mu.Unlock()
		if n > 0 && ok(m) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: last %v", what, m)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestGatewayIPFollowsPod (backend): the watch publishes a gateway only
// while that exact pod (UID) is Running, Ready and not terminating; a
// delete unpublishes at once (no refresh tick); a new pod with the same
// IP but another UID isn't trusted until it's Ready; a lost watch
// publishes nothing.
func TestGatewayIPFollowsPod(t *testing.T) {
	c := newCluster(t)
	b := c.backend(t)
	b.cfg.Sleep = func(ctx context.Context, d time.Duration) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Millisecond):
			return nil
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pods := c.typed.CoreV1().Pods(ns)
	pods.Create(ctx, readyPod("mesh--gw-a", "uid-a", "mesh", "10.42.0.5", true), metav1.CreateOptions{})
	r := &gwRecorder{}
	go b.WatchGateways(ctx, r.fn)
	r.waitFor(t, "A", func(m map[string]GatewayPod) bool { return m["mesh"] == GatewayPod{IP: "10.42.0.5", UID: "uid-a"} })
	// Deleted: gone at once.
	pods.Delete(ctx, "mesh--gw-a", metav1.DeleteOptions{})
	r.waitFor(t, "deleted", func(m map[string]GatewayPod) bool { return len(m) == 0 })
	// The same IP on another pod, not Ready: not trusted.
	pods.Create(ctx, readyPod("mesh--gw-b", "uid-b", "mesh", "10.42.0.5", false), metav1.CreateOptions{})
	time.Sleep(50 * time.Millisecond)
	r.mu.Lock()
	if len(r.last) != 0 {
		t.Errorf("a not-Ready pod reusing the IP was published: %v", r.last)
	}
	r.mu.Unlock()
	pods.Update(ctx, readyPod("mesh--gw-b", "uid-b", "mesh", "10.42.0.5", true), metav1.UpdateOptions{})
	r.waitFor(t, "B ready", func(m map[string]GatewayPod) bool { return m["mesh"] == GatewayPod{IP: "10.42.0.5", UID: "uid-b"} })
	// Terminating: unpublished.
	term := readyPod("mesh--gw-b", "uid-b", "mesh", "10.42.0.5", true)
	now := metav1.Now()
	term.DeletionTimestamp = &now
	pods.Update(ctx, term, metav1.UpdateOptions{})
	r.waitFor(t, "terminating", func(m map[string]GatewayPod) bool { return len(m) == 0 })
}

// A watch that can't be started publishes nothing.
func TestGatewayWatchLostPublishesNothing(t *testing.T) {
	c := newCluster(t)
	b := c.backend(t)
	c.typed.CoreV1().Pods(ns).Create(context.Background(), readyPod("mesh--gw-a", "uid-a", "mesh", "10.42.0.5", true), metav1.CreateOptions{})
	c.typed.PrependWatchReactor("pods", func(k8stesting.Action) (bool, watch.Interface, error) {
		return true, nil, errors.New("connection refused")
	})
	ctx, cancel := context.WithCancel(context.Background())
	r := &gwRecorder{}
	b.cfg.Sleep = func(context.Context, time.Duration) error { cancel(); return context.Canceled }
	b.WatchGateways(ctx, r.fn)
	if r.n == 0 || len(r.last) != 0 {
		t.Errorf("a lost watch published %v (%d calls)", r.last, r.n)
	}
}

func TestExposureDiff(t *testing.T) {
	want, _ := IngressObjects("app", EdgeNamespace, ns, ingressCases["forward-auth"])
	live := Exposure{}
	if d := live.Diff(want); !strings.Contains(d, "missing ingressroute/app--r-app") {
		t.Errorf("diff %q", d)
	}
	for _, o := range want {
		b, _ := json.Marshal(o.Object["spec"])
		live[exposureKey(o)] = string(b)
	}
	if d := live.Diff(want); d != "" {
		t.Errorf("equal: %q", d)
	}
	live["Middleware/app--m-x"] = "{}"
	if d := live.Diff(want); d != "unexpected middleware/app--m-x" {
		t.Errorf("extra: %q", d)
	}
}
