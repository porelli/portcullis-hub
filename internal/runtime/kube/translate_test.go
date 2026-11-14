package kube

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/compose-spec/compose-go/v2/cli"
	"github.com/compose-spec/compose-go/v2/types"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/portcullis/hub/internal/templates"
)

var update = flag.Bool("update", false, "rewrite the translator goldens")

const hubImage = "ghcr.io/porelli/portcullis-hub@sha256:1111111111111111111111111111111111111111111111111111111111111111"

// loadModel loads dir/compose.yml with dir/env (if any) as the hub does.
func loadModel(t *testing.T, dir, instance string) *types.Project {
	t.Helper()
	opts := []cli.ProjectOptionsFn{cli.WithName("portcullis-" + instance), cli.WithWorkingDirectory(dir),
		cli.WithEnv([]string{}), cli.WithProfiles([]string{"*"}), cli.WithConsistency(false), cli.WithResolvedPaths(false), cli.WithoutEnvironmentResolution}
	if _, err := os.Stat(filepath.Join(dir, "env")); err == nil {
		opts = append(opts, cli.WithEnvFiles(filepath.Join(dir, "env")), cli.WithDotEnv)
	}
	po, err := cli.NewProjectOptions([]string{filepath.Join(dir, "compose.yml")}, opts...)
	if err != nil {
		t.Fatal(err)
	}
	p, err := po.LoadProject(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// digests resolves every image of m to a fake digest.
func digests(m *types.Project) map[string]string {
	d := map[string]string{}
	for _, s := range m.Services {
		name, _, _ := strings.Cut(s.Image, "@")
		d[s.Image] = name + "@sha256:" + strings.Repeat("ab", 32)
	}
	return d
}

func baseInput(t *testing.T, dir, instance string) Input {
	m := loadModel(t, dir, instance)
	in := Input{Instance: instance, Template: "echo", Namespace: "portcullis-apps", Model: m, Digests: digests(m), HubImage: hubImage,
		BindRoots: []string{"/srv", "/mnt", "/media"},
		Settings: Settings{PodCIDR: "10.42.0.0/16", ServiceCIDR: "10.43.0.0/16", TraefikServiceIP: "10.43.0.20", WGEdgeServiceIP: "10.43.0.22", Domain: "example.org",
			LocalNetworks: []string{"192.168.1.0/24", "fd00::/8"}, NodeAddresses: []string{"192.0.2.10"}}}
	if b, err := os.ReadFile(filepath.Join(dir, "case.json")); err == nil {
		if err := json.Unmarshal(b, &in); err != nil {
			t.Fatal(err)
		}
	}
	tf := filepath.Join(dir, "templates")
	filepath.WalkDir(tf, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			b, _ := os.ReadFile(p)
			rel, _ := filepath.Rel(tf, p)
			if in.TemplateFiles == nil {
				in.TemplateFiles = map[string][]byte{}
			}
			in.TemplateFiles[filepath.ToSlash(rel)] = b
		}
		return nil
	})
	return in
}

func TestTranslateGoldens(t *testing.T) {
	cases, _ := filepath.Glob("testdata/translate/*")
	if len(cases) < 6 {
		t.Fatalf("%d golden cases", len(cases))
	}
	for _, dir := range cases {
		t.Run(filepath.Base(dir), func(t *testing.T) {
			in := baseInput(t, dir, filepath.Base(dir))
			p, err := Translate(in)
			var got []byte
			if err != nil {
				got = []byte("refused: " + err.Error() + "\n")
			} else if got, err = PlanYAML(p); err != nil {
				t.Fatal(err)
			}
			want := filepath.Join(dir, "want.yaml")
			if *update {
				os.WriteFile(want, got, 0o644)
				return
			}
			w, err := os.ReadFile(want)
			if err != nil {
				t.Fatal(err)
			}
			if string(w) != string(got) {
				t.Errorf("golden %s differs (go test -run TranslateGoldens -update):\n%s", want, got)
			}
		})
	}
}

func modelOf(t *testing.T, compose, instance string) *types.Project {
	t.Helper()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "compose.yml"), []byte(compose), 0o644)
	return loadModel(t, dir, instance)
}

func inputOf(t *testing.T, compose, instance string) Input {
	m := modelOf(t, compose, instance)
	return Input{Instance: instance, Template: "x", Namespace: "portcullis-apps", Model: m, Digests: digests(m), HubImage: hubImage, BindRoots: []string{"/srv"},
		Settings: Settings{PodCIDR: "10.42.0.0/16", ServiceCIDR: "10.43.0.0/16", NodeAddresses: []string{"192.0.2.10"}}}
}

func TestTranslateNameCollisionRefused(t *testing.T) {
	// Two compose names giving one object name can't happen any more on
	// Kubernetes (names must be DNS labels without "--"): the refusal.
	_, err := Translate(inputOf(t, "services:\n  my_db:\n    image: docker.io/library/postgres:17\n  my-db:\n    image: docker.io/library/postgres:17\n", "app"))
	if !strings.Contains(refusedErr(err), "my_db") {
		t.Fatalf("collision: %v", err)
	}
	inst, svc := strings.Repeat("i", 40), strings.Repeat("s", 30)
	a, b := ObjectName(inst, svc), ObjectName(inst, svc+"x")
	if len(a) > 63 || len(b) > 63 || a == b {
		t.Errorf("hashed names %q %q", a, b)
	}
	if ObjectName("App_1", "web.front") != "app-1--web-front" {
		t.Errorf("ObjectName = %q", ObjectName("App_1", "web.front"))
	}
	// The "--" separator keeps instance a-b's service c apart from
	// instance a's service b-c.
	if ObjectName("a-b", "c") == ObjectName("a", "b-c") {
		t.Error("names collide across instances")
	}
}

func TestTranslateObjectTooLargeRefused(t *testing.T) {
	in := inputOf(t, "services:\n  web:\n    image: docker.io/library/nginx:1.29\n    volumes:\n      - ./templates/x/big:/big:ro\n", "app")
	in.TemplateFiles = map[string][]byte{"big": make([]byte, 1<<20+1)}
	_, err := Translate(in)
	if err == nil || err.Error() != "template files for x exceed 1 MiB" {
		t.Fatalf("err = %v", err)
	}
}

func objectsOf(t *testing.T, in Input) []*unstructured.Unstructured {
	t.Helper()
	p, err := Translate(in)
	if err != nil {
		t.Fatal(err)
	}
	return p.Objects()
}

func TestTranslateLabelsOnlyFromTranslator(t *testing.T) {
	in := inputOf(t, "services:\n  web:\n    image: docker.io/library/nginx:1.29\n    labels:\n      portcullis.io/net-portcullis: \"true\"\n      portcullis.io/instance: other\n", "app")
	for _, o := range objectsOf(t, in) {
		if o.GetKind() != "Deployment" {
			continue
		}
		l, _, _ := unstructured.NestedStringMap(o.Object, "spec", "template", "metadata", "labels")
		if _, ok := l["portcullis.io/net-portcullis"]; ok || l[LabelInstance] != "app" {
			t.Errorf("pod labels %v", l)
		}
		ann, _, _ := unstructured.NestedStringMap(o.Object, "spec", "template", "metadata", "annotations")
		if !strings.Contains(ann[AnnotationComposeLabels], "portcullis.io/net-portcullis") {
			t.Errorf("annotations %v", ann)
		}
	}
}

func TestTranslateNoSecretInPodSpec(t *testing.T) {
	in := inputOf(t, "services:\n  web:\n    image: docker.io/library/nginx:1.29\n    environment:\n      DB_PASSWORD: s3cr3t-value-0123\n      PLAIN: also-hidden-4567\n  worker:\n    image: docker.io/library/alpine:3.24.3\n    environment:\n      TOKEN: tok-89ab\n", "app")
	found := false
	for _, o := range objectsOf(t, in) {
		b, _ := json.Marshal(o.Object)
		switch o.GetKind() {
		case "Deployment", "Job":
			for _, v := range []string{"s3cr3t-value-0123", "also-hidden-4567", "tok-89ab"} {
				if strings.Contains(string(b), v) {
					t.Errorf("%s %s carries %s", o.GetKind(), o.GetName(), v)
				}
			}
			if strings.Contains(o.GetName(), "worker") && strings.Contains(string(b), "DB_PASSWORD") {
				t.Error("worker gets web's variables")
			}
		case "Secret":
			found = found || strings.Contains(string(b), "czNjcjN0")
		}
	}
	if !found {
		t.Error("the env Secret doesn't hold the values")
	}
}

func TestTranslateStartPeriodIsStartupProbe(t *testing.T) {
	in := inputOf(t, "services:\n  web:\n    image: docker.io/library/nginx:1.29\n    healthcheck:\n      test: [\"CMD-SHELL\", \"wget -qO- localhost\"]\n      interval: 10s\n      timeout: 5s\n      retries: 3\n      start_period: 300s\n", "app")
	for _, o := range objectsOf(t, in) {
		if o.GetKind() != "Deployment" {
			continue
		}
		cs, _, _ := unstructured.NestedSlice(o.Object, "spec", "template", "spec", "containers")
		c := cs[0].(map[string]any)
		sp := c["startupProbe"].(map[string]any)
		if sp["failureThreshold"] != int64(33) || sp["periodSeconds"] != int64(10) {
			t.Errorf("startupProbe %v", sp)
		}
		if c["livenessProbe"].(map[string]any)["failureThreshold"] != int64(6) || c["readinessProbe"].(map[string]any)["failureThreshold"] != int64(3) {
			t.Errorf("probes %v", c)
		}
		b, _ := json.Marshal(o.Object)
		if strings.Contains(string(b), "initialDelaySeconds") {
			t.Error("initialDelaySeconds set")
		}
		ex := sp["exec"].(map[string]any)["command"].([]any)
		if len(ex) != 3 || ex[0] != "sh" || ex[2] != "wget -qO- localhost" {
			t.Errorf("exec %v", ex)
		}
	}
}

// runtimeVector is one entry of templates' testdata/runtime_vectors.json.
type runtimeVector struct {
	Name     string            `json:"name"`
	Runtime  string            `json:"runtime"`
	Compose  string            `json:"compose"`
	Env      map[string]string `json:"env"`
	Settings map[string]string `json:"settings"`
	Ports    []struct {
		Key      string `json:"key"`
		Port     int    `json:"port"`
		Protocol string `json:"protocol"`
		Service  string `json:"service"`
	} `json:"ports"`
	Want templates.Compat `json:"want"`
}

// TestTranslatorRefusesWhatCompatRefuses: every Kubernetes vector goes
// through RuntimeCompat and the translator; a refused verdict is a
// translator refusal with one of its reasons, ok/degraded translate.
func TestTranslatorRefusesWhatCompatRefuses(t *testing.T) {
	b, err := os.ReadFile("../../templates/testdata/runtime_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []runtimeVector
	if err := json.Unmarshal(b, &vs); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, v := range vs {
		if v.Runtime != "kubernetes" {
			continue
		}
		n++
		var m templates.Manifest
		env := map[string]string{}
		for k, val := range v.Env {
			env[k] = val
		}
		for _, p := range v.Ports {
			m.Ports = append(m.Ports, templates.Port{Key: p.Key, Container: p.Port, Default: p.Port, Protocol: p.Protocol, Service: p.Service})
		}
		got := templates.RuntimeCompat("kubernetes", []byte(v.Compose), m, env, 80)
		// The compose the translator sees: the vector's, with the
		// manifest ports published as the Hub's compose would.
		compose := v.Compose
		dir := t.TempDir()
		var envLines []string
		for k, val := range v.Env {
			envLines = append(envLines, k+"="+val)
		}
		os.WriteFile(filepath.Join(dir, "env"), []byte(strings.Join(envLines, "\n")+"\n"), 0o644)
		os.WriteFile(filepath.Join(dir, "compose.yml"), []byte(compose), 0o644)
		model := loadModel(t, dir, "vec")
		for _, p := range v.Ports {
			svc := p.Service
			if svc == "" {
				for _, name := range model.ServiceNames() {
					svc = name
					break
				}
			}
			s := model.Services[svc]
			s.Ports = append(s.Ports, types.ServicePortConfig{Target: uint32(p.Port), Published: itoa(p.Port), Protocol: p.Protocol})
			model.Services[svc] = s
		}
		in := Input{Instance: "vec", Template: "echo", Namespace: "portcullis-apps", Model: model, Digests: digests(model), HubImage: hubImage, BindRoots: templates.DefaultKubeBindRoots,
			TemplateFiles: map[string][]byte{"conf/x": []byte("x")}, Settings: Settings{PodCIDR: "10.42.0.0/16", ServiceCIDR: "10.43.0.0/16", NodeAddresses: []string{"192.0.2.10"}}}
		_, terr := Translate(in)
		switch got.Status {
		case templates.CompatRefused:
			var r *ErrRefused
			if !errors.As(terr, &r) {
				t.Errorf("%s: compat refused (%v), the translator didn't: %v", v.Name, got.Reasons, terr)
				continue
			}
			ok := false
			for _, reason := range got.Reasons {
				ok = ok || reason == r.Reason
			}
			if !ok {
				t.Errorf("%s: the translator refused %q, compat %q", v.Name, r.Reason, got.Reasons)
			}
		default:
			if terr != nil && !strings.Contains(terr.Error(), "template file") {
				t.Errorf("%s: compat %s, the translator refused: %v", v.Name, got.Status, terr)
			}
		}
	}
	if n < 10 {
		t.Fatalf("%d kubernetes vectors", n)
	}
}

// A published port keeps its binding: the wildcard is a LoadBalancer,
// loopback no Service, a specific address refused; a lan_only port with
// no Local networks is refused.
func TestTranslatePortBindings(t *testing.T) {
	in := inputOf(t, "services:\n  app:\n    image: docker.io/library/nginx:1.29\n    ports:\n      - \"127.0.0.1:9081:80\"\n      - \"9083:80\"\n", "pb")
	var svcs []string
	for _, o := range objectsOf(t, in) {
		if typ, _, _ := unstructured.NestedString(o.Object, "spec", "type"); o.GetKind() == "Service" && typ == "LoadBalancer" {
			svcs = append(svcs, o.GetName())
		}
	}
	if len(svcs) != 1 || svcs[0] != "pb--app-9083-tcp" {
		t.Errorf("services %v", svcs)
	}
	in = inputOf(t, "services:\n  app:\n    image: docker.io/library/nginx:1.29\n    ports:\n      - \"192.168.1.5:9080:80\"\n", "pb")
	if _, err := Translate(in); refusedErr(err) != "service app publishes 9080 on 192.168.1.5 (not on Kubernetes)" {
		t.Errorf("specific address: %v", err)
	}
	in = inputOf(t, "services:\n  app:\n    image: docker.io/library/nginx:1.29\n    ports:\n      - \"445:445\"\n", "pb")
	in.LanOnly = map[int]bool{445: true}
	if _, err := Translate(in); !strings.Contains(refusedErr(err), "for the local networks only") {
		t.Errorf("lan_only without networks: %v", err)
	}
	in.Settings.LocalNetworks = []string{"fd00::/8"}
	if _, err := Translate(in); !strings.Contains(refusedErr(err), "for the local networks only") {
		t.Errorf("lan_only with IPv6 networks only: %v", err)
	}
}

// TestTranslateRootRefused: a long-running service running as uid 0 is
// refused (core's admission lets only the Hub's helpers and the one-shot
// shape run as root); a gid 0 alone is not root.
func TestTranslateRootRefused(t *testing.T) {
	for _, u := range []string{"0:0", "0", "00:1000"} {
		in := inputOf(t, "services:\n  samba:\n    image: docker.io/library/nginx:1.29\n    user: \""+u+"\"\n", "rr")
		if _, err := Translate(in); refusedErr(err) != "service samba runs as root (user 0)" {
			t.Errorf("%s: %v", u, err)
		}
	}
	in := inputOf(t, "services:\n  app:\n    image: docker.io/library/nginx:1.29\n    user: \"1000:0\"\n", "rr")
	if _, err := Translate(in); err != nil {
		t.Errorf("1000:0: %v", err)
	}
}

// oneShotCompose: app waits for perms, a root one-shot chown job.
func oneShotCompose(perms string) string {
	return "services:\n  app:\n    image: docker.io/library/nginx:1.29\n    depends_on:\n      perms:\n        condition: service_completed_successfully\n" +
		"  perms:\n    image: docker.io/library/alpine:3.24\n    user: \"0:1000\"\n    restart: \"no\"\n    read_only: true\n" + perms
}

// TestTranslateOneShotRoot: a one-shot job may run as uid 0 only in the
// ruled shape — restart no/on-failure, a Job, no ports, no routes,
// cap_drop ALL, cap_add within CHOWN, DAC_OVERRIDE, FOWNER — and its
// pod template is labelled portcullis.io/one-shot: "true", no privilege
// escalation, its read_only kept, no token.
func TestTranslateOneShotRoot(t *testing.T) {
	ok := "    cap_drop: [ALL]\n    cap_add: [CHOWN, DAC_OVERRIDE, FOWNER]\n"
	var job *unstructured.Unstructured
	for _, o := range objectsOf(t, inputOf(t, oneShotCompose(ok), "os")) {
		if o.GetKind() == "Job" {
			job = o
		}
		if o.GetKind() == "Deployment" {
			if l, _, _ := unstructured.NestedStringMap(o.Object, "spec", "template", "metadata", "labels"); l[LabelOneShot] != "" {
				t.Errorf("deployment labelled one-shot: %v", l)
			}
		}
	}
	if job == nil || job.GetName() != "os--perms" {
		t.Fatalf("no job: %v", job)
	}
	l, _, _ := unstructured.NestedStringMap(job.Object, "spec", "template", "metadata", "labels")
	if l[LabelOneShot] != "true" {
		t.Errorf("labels %v", l)
	}
	if v, _, _ := unstructured.NestedBool(job.Object, "spec", "template", "spec", "automountServiceAccountToken"); v {
		t.Error("token")
	}
	cs, _, _ := unstructured.NestedSlice(job.Object, "spec", "template", "spec", "containers")
	sc := cs[0].(map[string]any)["securityContext"].(map[string]any)
	if sc["runAsUser"] != int64(0) || sc["allowPrivilegeEscalation"] != false || sc["readOnlyRootFilesystem"] != true || sc["privileged"] != nil {
		t.Errorf("security context %v", sc)
	}
	caps := sc["capabilities"].(map[string]any)
	if fmt.Sprint(caps["drop"]) != "[ALL]" || fmt.Sprint(caps["add"]) != "[CHOWN DAC_OVERRIDE FOWNER]" {
		t.Errorf("caps %v", caps)
	}
	why := "service perms runs as root (user 0): only a one-shot job (restart no or on-failure) with cap_drop [ALL], cap_add within CHOWN, DAC_OVERRIDE, FOWNER, no ports and no routes may"
	for name, c := range map[string]string{
		"no cap_drop":      "    cap_add: [CHOWN]\n",
		"cap_drop not ALL": "    cap_drop: [NET_RAW]\n",
		"SETUID":           "    cap_drop: [ALL]\n    cap_add: [CHOWN, SETUID]\n",
		"a port":           ok + "    ports: [\"8080:80\"]\n",
		"a route":          ok + "    labels:\n      traefik.enable: \"true\"\n      traefik.http.routers.p.rule: Host(`p.example.org`)\n",
		"restart always":   strings.Replace(ok, "    cap_drop", "    restart: always\n    cap_drop", 1),
	} {
		compose := oneShotCompose(c)
		if name == "restart always" {
			compose = strings.Replace(compose, "    restart: \"no\"\n", "", 1)
		}
		if _, err := Translate(inputOf(t, compose, "os")); refusedErr(err) != why && refusedErr(err) != "service perms runs as root (user 0)" {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestTranslateClusterIPServices: every pod with a port gets its
// ClusterIP Service <instance>--<pod> (contract §11.2): Traefik's
// loadbalancer ports, the AI companion ports, expose and the published
// ports' targets; a route's Service ref names an existing Service port;
// a pod without any port gets none.
func TestTranslateClusterIPServices(t *testing.T) {
	in := inputOf(t, "services:\n  web:\n    image: docker.io/library/nginx:1.29\n    expose: [\"9000\"]\n    labels:\n"+
		"      traefik.enable: \"true\"\n      traefik.http.routers.web.rule: Host(`a.example.org`)\n      traefik.http.services.web.loadbalancer.server.port: \"8080\"\n"+
		"  db:\n    image: docker.io/library/postgres:17\n    expose: [\"5432\"]\n    ports: [\"127.0.0.1:15432:5432\"]\n"+
		"  tools:\n    image: docker.io/library/nginx:1.29\n"+
		"  job:\n    image: docker.io/library/alpine:3.24\n", "cs")
	in.CompanionPorts = map[string][]int{"tools": {7000}}
	got := map[string][]int64{}
	var routeRef map[string]any
	for _, o := range objectsOf(t, in) {
		if o.GetKind() == "IngressRoute" {
			routeRef = o.Object["spec"].(map[string]any)["routes"].([]any)[0].(map[string]any)["services"].([]any)[0].(map[string]any)
		}
		if o.GetKind() != "Service" {
			continue
		}
		typ, _, _ := unstructured.NestedString(o.Object, "spec", "type")
		if typ == "LoadBalancer" || o.GetName() == "cs--pods" {
			continue
		}
		if typ != "" && typ != "ClusterIP" {
			t.Errorf("%s: type %s", o.GetName(), typ)
		}
		if ip, ok, _ := unstructured.NestedString(o.Object, "spec", "clusterIP"); ok && ip != "" {
			t.Errorf("%s: clusterIP %s", o.GetName(), ip)
		}
		sel, _, _ := unstructured.NestedStringMap(o.Object, "spec", "selector")
		if sel[LabelInstance] != "cs" {
			t.Errorf("%s: selector %v", o.GetName(), sel)
		}
		ports, _, _ := unstructured.NestedSlice(o.Object, "spec", "ports")
		for _, p := range ports {
			got[o.GetName()] = append(got[o.GetName()], p.(map[string]any)["port"].(int64))
		}
	}
	want := map[string][]int64{"cs--web": {8080, 9000}, "cs--db": {5432}, "cs--tools": {7000}}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("services %v, want %v", got, want)
	}
	if routeRef["name"] != "cs--web" || routeRef["port"] != int64(8080) {
		t.Errorf("route ref %v", routeRef)
	}
}

// TestTranslateCompanionAliasService: a rendered AI companion gets a
// ClusterIP Service named its gate alias portcullis-mcp-<id>--<c> (the
// name mcp-gate's upstream must carry) on its port, selecting its pod;
// mcp-gate is admitted on that port; a foreign alias or an unknown
// service is refused.
func TestTranslateCompanionAliasService(t *testing.T) {
	compose := "services:\n  app:\n    image: docker.io/library/nginx:1.29\n  tools:\n    image: docker.io/library/nginx:1.29\n    network_mode: service:app\n"
	in := inputOf(t, compose, "ca")
	in.Companions = []Companion{{Service: "tools", Alias: "portcullis-mcp-ca--tools", Port: 7000}}
	var alias *unstructured.Unstructured
	mcpIngress := false
	for _, o := range objectsOf(t, in) {
		if o.GetKind() == "Service" && o.GetName() == "portcullis-mcp-ca--tools" {
			alias = o
		}
		if o.GetKind() == "NetworkPolicy" && strings.Contains(fmt.Sprint(o.Object), "mcp-gate") && strings.Contains(fmt.Sprint(o.Object), "7000") {
			mcpIngress = true
		}
	}
	if alias == nil {
		t.Fatal("no alias Service")
	}
	sel, _, _ := unstructured.NestedStringMap(alias.Object, "spec", "selector")
	ports, _, _ := unstructured.NestedSlice(alias.Object, "spec", "ports")
	if sel[LabelInstance] != "ca" || sel[LabelService] != "app" || len(ports) != 1 || ports[0].(map[string]any)["port"] != int64(7000) {
		t.Errorf("alias Service %v", alias.Object["spec"])
	}
	if alias.GetLabels()[LabelInstance] != "ca" {
		t.Errorf("labels %v", alias.GetLabels())
	}
	if !mcpIngress {
		t.Error("no mcp-gate ingress on 7000")
	}
	// The companion's pod carries portcullis.io/mcp-companion (core's
	// mcp-gate egress selects it); no other pod does.
	in.Companions = []Companion{{Service: "tools", Alias: "portcullis-mcp-ca--tools", Port: 7000}}
	in2 := in
	in2.Model = modelOf(t, compose+"  other:\n    image: docker.io/library/nginx:1.29\n", "ca")
	in2.Digests = digests(in2.Model)
	for _, o := range objectsOf(t, in2) {
		if o.GetKind() != "Deployment" {
			continue
		}
		l, _, _ := unstructured.NestedStringMap(o.Object, "spec", "template", "metadata", "labels")
		if want := map[string]string{"ca--app": "true", "ca--other": ""}[o.GetName()]; l[LabelMCPCompanion] != want {
			t.Errorf("%s: mcp-companion %q", o.GetName(), l[LabelMCPCompanion])
		}
	}
	for _, c := range []Companion{{Service: "tools", Alias: "portcullis-mcp-other--tools", Port: 7000}, {Service: "nope", Alias: "portcullis-mcp-ca--nope", Port: 7000},
		{Service: "tools", Alias: "portcullis-mcp-ca--tools", Port: 0}, {Service: "tools", Alias: "portcullis-mcp-ca--Tools", Port: 7000}} {
		in.Companions = []Companion{c}
		if _, err := Translate(in); refusedErr(err) == "" {
			t.Errorf("%+v: %v", c, err)
		}
	}
}

// TestTranslatePodDNS: compose service names resolve to the instance's
// pods: a headless Service <instance>--pods (publishNotReadyAddresses),
// each pod hostname = its compose service, subdomain = that Service, the
// instance's search domain first; the vpn gateway's netns members share
// their owner's pod (no name of their own, as on Docker). Names that
// can't be pod DNS names are refused.
func TestTranslatePodDNS(t *testing.T) {
	compose := "services:\n  web:\n    image: docker.io/library/nginx:1.29\n  db:\n    image: docker.io/library/postgres:17\n" +
		"  side:\n    image: docker.io/library/nginx:1.29\n    network_mode: service:web\n"
	var headless *unstructured.Unstructured
	pods := map[string]map[string]any{}
	for _, o := range objectsOf(t, inputOf(t, compose, "dn")) {
		switch o.GetKind() {
		case "Service":
			if o.GetName() == "dn--pods" {
				headless = o
			}
		case "Deployment", "Job":
			spec, _, _ := unstructured.NestedMap(o.Object, "spec", "template", "spec")
			pods[o.GetName()] = spec
		}
	}
	if headless == nil {
		t.Fatal("no headless Service")
	}
	spec := headless.Object["spec"].(map[string]any)
	if spec["clusterIP"] != "None" || spec["publishNotReadyAddresses"] != true || fmt.Sprint(spec["selector"]) != "map[portcullis.io/instance:dn]" {
		t.Errorf("headless %v", spec)
	}
	if len(pods) != 2 {
		t.Fatalf("pods %v", slices.Sorted(mapKeys(pods)))
	}
	for name, svc := range map[string]string{"dn--web": "web", "dn--db": "db"} {
		p := pods[name]
		if p["hostname"] != svc || p["subdomain"] != "dn--pods" {
			t.Errorf("%s: hostname %v subdomain %v", name, p["hostname"], p["subdomain"])
		}
		if s := fmt.Sprint(p["dnsConfig"]); s != "map[searches:[dn--pods.portcullis-apps.svc.cluster.local]]" {
			t.Errorf("%s: dnsConfig %s", name, s)
		}
	}
	for c, why := range map[string]string{
		"services:\n  my_db:\n    image: docker.io/library/postgres:17\n": "service my_db: its name isn't a DNS label without \"--\" (not on Kubernetes)",
		"services:\n  Web:\n    image: docker.io/library/nginx:1.29\n":    "service Web: its name isn't a DNS label without \"--\" (not on Kubernetes)",
		"services:\n  a--b:\n    image: docker.io/library/nginx:1.29\n":   "service a--b: its name isn't a DNS label without \"--\" (not on Kubernetes)",
	} {
		if _, err := Translate(inputOf(t, c, "dn")); refusedErr(err) != why {
			t.Errorf("%q: %v", c, err)
		}
	}
	// The Hub's own companion alias is the alias Service, not refused.
	in := inputOf(t, "services:\n  web:\n    image: docker.io/library/nginx:1.29\n    networks:\n      default:\n        aliases: [portcullis-mcp-dn--tok]\n", "dn")
	in.Companions = []Companion{{Service: "web", Alias: "portcullis-mcp-dn--tok", Port: 80}}
	if _, err := Translate(in); err != nil {
		t.Errorf("companion alias: %v", err)
	}
}

// TestTranslateOneShotRootMounts: a root one-shot job mounts no host path
// (on Kubernetes a host bind is a shared folder), writable or not; its
// own PVC and emptyDir are fine; a root group
// is refused; no fsGroup 0 is ever
// emitted.
func TestTranslateOneShotRootMounts(t *testing.T) {
	ok := "    cap_drop: [ALL]\n    cap_add: [CHOWN]\n"
	for vols, why := range map[string]string{
		"    volumes: [\"/srv/share:/data\"]\n":    "service perms runs as root with a host bind",
		"    volumes: [\"/srv/share:/data:ro\"]\n": "service perms runs as root with a host bind",
	} {
		if _, err := Translate(inputOf(t, oneShotCompose(ok+vols), "os")); refusedErr(err) != why {
			t.Errorf("%q: %v", vols, err)
		}
	}
	compose := strings.Replace(oneShotCompose(ok+"    volumes: [\"data:/data\", \"/scratch\"]\n"),
		"  app:\n    image: docker.io/library/nginx:1.29\n", "  app:\n    image: docker.io/library/nginx:1.29\n    user: \"1000:1000\"\n    volumes: [\"data:/srv/data\"]\n", 1)
	in := inputOf(t, compose+"volumes:\n  data: {}\n", "os")
	for _, o := range objectsOf(t, in) {
		if g, ok, _ := unstructured.NestedInt64(o.Object, "spec", "template", "spec", "securityContext", "fsGroup"); ok && g == 0 {
			t.Errorf("%s: fsGroup 0", o.GetName())
		}
	}
	// A root job's volume must be owned by a non-root service.
	if _, err := Translate(inputOf(t, oneShotCompose(ok+"    volumes: [\"data:/data\"]\n")+"volumes:\n  data: {}\n", "os")); !strings.Contains(refusedErr(err), "no non-root service mounts") {
		t.Errorf("unowned root volume: %v", err)
	}
	for _, u := range []string{"0:0\"", "0\"", "0:1000\"\n    group_add: [\"0\"]"} {
		in := inputOf(t, "services:\n  app:\n    image: docker.io/library/nginx:1.29\n    user: \""+u+"\n    restart: \"no\"\n    cap_drop: [ALL]\n", "fg")
		if _, err := Translate(in); !strings.Contains(refusedErr(err), "runs as root with group 0") {
			t.Errorf("%q: %v", u, err)
		}
	}
	for _, u := range []string{"1000:0", "0:1000"} {
		in := inputOf(t, "services:\n  app:\n    image: docker.io/library/nginx:1.29\n    user: \""+u+"\"\n    restart: \"no\"\n    cap_drop: [ALL]\n", "fg")
		for _, o := range objectsOf(t, in) {
			if g, ok, _ := unstructured.NestedInt64(o.Object, "spec", "template", "spec", "securityContext", "fsGroup"); ok && g == 0 {
				t.Errorf("%s: fsGroup 0", u)
			}
		}
	}
}

// TestTranslateAliases: a network alias or container_name gets a
// ClusterIP Service <instance>--<alias> on the aliased pod's ports, in
// the first step (before any pod), and Plan.Aliases names it; refused:
// an alias that isn't a DNS label, is a compose name, names two
// services, or whose pod declares no port.
func TestTranslateAliases(t *testing.T) {
	compose := "services:\n  web:\n    image: docker.io/library/nginx:1.29\n    expose: [\"8080\"]\n    container_name: www\n    networks:\n      default:\n        aliases: [web-internal]\n" +
		"  side:\n    image: docker.io/library/nginx:1.29\n    network_mode: service:web\n"
	p, err := Translate(inputOf(t, compose, "al"))
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(p.Aliases) != "map[web-internal:al--web-internal www:al--www]" {
		t.Errorf("aliases %v", p.Aliases)
	}
	found := 0
	for _, o := range p.Steps[0].Objects {
		if o.GetKind() == "Service" && (o.GetName() == "al--web-internal" || o.GetName() == "al--www") {
			found++
			sel, _, _ := unstructured.NestedStringMap(o.Object, "spec", "selector")
			ports, _, _ := unstructured.NestedSlice(o.Object, "spec", "ports")
			if sel[LabelService] != "web" || len(ports) != 1 || ports[0].(map[string]any)["port"] != int64(8080) {
				t.Errorf("%s: %v", o.GetName(), o.Object["spec"])
			}
		}
	}
	if found != 2 {
		t.Errorf("%d alias Services in the first step", found)
	}
	img := "    image: docker.io/library/nginx:1.29\n"
	for c, why := range map[string]string{
		"services:\n  web:\n" + img + "    expose: [\"80\"]\n    networks:\n      default:\n        aliases: [Web_1]\n":                                                                                                         "service web answers to alias Web_1, not a DNS label without \"--\" (not on Kubernetes)",
		"services:\n  web:\n" + img + "    expose: [\"80\"]\n    networks:\n      default:\n        aliases: [db]\n  db:\n" + img:                                                                                               "service web answers to alias db, also a compose service name",
		"services:\n  a:\n" + img + "    expose: [\"80\"]\n    networks:\n      default:\n        aliases: [x-internal]\n  b:\n" + img + "    expose: [\"80\"]\n    networks:\n      default:\n        aliases: [x-internal]\n": "alias x-internal names two services (a, b)",
		"services:\n  web:\n" + img + "    networks:\n      default:\n        aliases: [web-internal]\n":                                                                                                                        "service web answers to alias web-internal but serves no declared port (expose it)",
	} {
		if _, err := Translate(inputOf(t, c, "al")); refusedErr(err) != why {
			t.Errorf("%q: %v", c, err)
		}
	}
}

// TestTemplateFilesInstanceOwned: the template-folder binds of any pod
// come from one ConfigMap the instance owns, <instance>--tpl-<hash10>
// (labelled with the instance), mounted read-only; two instances of one
// template never share it; a root one-shot job may mount it.
func TestTemplateFilesInstanceOwned(t *testing.T) {
	compose := oneShotCompose("    cap_drop: [ALL]\n    cap_add: [CHOWN]\n    volumes: [\"./templates/x/fetch.sh:/fetch.sh:ro\"]\n")
	names := map[string]bool{}
	for _, inst := range []string{"a1", "a2"} {
		in := inputOf(t, compose, inst)
		in.TemplateFiles = map[string][]byte{"fetch.sh": []byte("echo")}
		var cm string
		for _, o := range objectsOf(t, in) {
			if o.GetKind() == "ConfigMap" && strings.HasPrefix(o.GetName(), inst+"--tpl-") {
				cm = o.GetName()
				if o.GetLabels()[LabelInstance] != inst || len(cm) != len(inst)+len("--tpl-")+10 {
					t.Errorf("%s labels %v", cm, o.GetLabels())
				}
			}
			if o.GetKind() == "Job" {
				vs, _, _ := unstructured.NestedSlice(o.Object, "spec", "template", "spec", "volumes")
				if !strings.Contains(fmt.Sprint(vs), "name:"+inst+"--tpl-") {
					t.Errorf("job volumes %v", vs)
				}
			}
		}
		if cm == "" {
			t.Fatalf("%s: no instance-owned template ConfigMap", inst)
		}
		names[cm] = true
	}
	if len(names) != 2 {
		t.Errorf("shared: %v", names)
	}
}
