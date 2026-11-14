package kube

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
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
	_, err := Translate(inputOf(t, "services:\n  my_db:\n    image: docker.io/library/postgres:17\n  my-db:\n    image: docker.io/library/postgres:17\n", "app"))
	var r *ErrRefused
	if !errors.As(err, &r) || !strings.Contains(r.Reason, "my_db") || !strings.Contains(r.Reason, "my-db") {
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
		for name, s := range model.Services {
			if s.User == "" {
				s.User = "10001"
				model.Services[name] = s
			}
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
