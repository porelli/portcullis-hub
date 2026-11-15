package templates

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// placementVector is one entry of testdata/placement_vectors.json, the
// authoritative copy of portcullis-templates tests/placement_vectors.json
// (its lint compares the two byte for byte): compose, the manifest (a
// JSON object, decoded as the Hub decodes manifest.yaml), the instance
// env, the server's folder roots and the verdict.
type placementVector struct {
	Name      string            `json:"name"`
	Compose   string            `json:"compose"`
	Manifest  json.RawMessage   `json:"manifest"`
	Env       map[string]string `json:"env"`
	BindRoots []string          `json:"bind_roots"`
	Want      struct {
		PrimaryOnly bool     `json:"primary_only"`
		Reasons     []string `json:"reasons"`
	} `json:"want"`
}

func TestPlacementVectors(t *testing.T) {
	b, err := os.ReadFile("testdata/placement_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []placementVector
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&vs); err != nil {
		t.Fatal(err)
	}
	if len(vs) < 20 {
		t.Fatalf("%d vectors", len(vs))
	}
	// Every reason appears in some vector.
	need := map[string]bool{"mounts the core volume": true, "has a Traefik TCP/UDP router": true, "has a per-person secret option": true,
		"has AI companions": true, "is an AI page": true, "is a VPN provider": true, "uses host-gateway": true, "outside the server's folder roots": true,
		"is marked placement: primary_only": true, "uses a non-HTTP backend scheme": true,
		"passes a host device": true, "adds the capability": true, "adds an unknown capability": true}
	clean := 0
	for _, v := range vs {
		var m Manifest
		if err := yaml.Unmarshal(v.Manifest, &m); err != nil {
			t.Errorf("%s: manifest: %v", v.Name, err)
			continue
		}
		if err := ValidateManifest(&m); err != nil {
			t.Errorf("%s: manifest: %v", v.Name, err)
		}
		po, reasons := Placement([]byte(v.Compose), m, v.Env, v.BindRoots)
		if po != v.Want.PrimaryOnly || !reflect.DeepEqual(reasons, v.Want.Reasons) {
			t.Errorf("%s:\n got %v %#v\nwant %v %#v", v.Name, po, reasons, v.Want.PrimaryOnly, v.Want.Reasons)
		}
		if po != (len(reasons) > 0) || reasons == nil {
			t.Errorf("%s: primary_only %v with reasons %#v", v.Name, po, reasons)
		}
		if !po {
			clean++
		}
		for _, r := range v.Want.Reasons {
			for k := range need {
				if strings.Contains(r, k) {
					delete(need, k)
				}
			}
		}
	}
	for k := range need {
		t.Errorf("no vector for the reason %q", k)
	}
	if clean < 5 {
		t.Errorf("%d clean vectors", clean)
	}
}

func TestPlacementField(t *testing.T) {
	for _, v := range []string{"", PlacementAny, PlacementPrimaryOnly} {
		if err := ValidateManifest(&Manifest{Placement: v}); err != nil && strings.Contains(err.Error(), "placement") {
			t.Errorf("%q: %v", v, err)
		}
	}
	for _, v := range []string{"primary", "worker", "Primary_Only", " any"} {
		if err := ValidateManifest(&Manifest{Placement: v}); err == nil || !strings.Contains(err.Error(), "placement") {
			t.Errorf("%q: %v", v, err)
		}
	}
}

func loadFixture(t *testing.T, dir string) ([]byte, Manifest) {
	t.Helper()
	mb, err := os.ReadFile(filepath.Join(dir, "manifest.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var m Manifest
	if err := yaml.Unmarshal(mb, &m); err != nil {
		t.Fatal(err)
	}
	c, err := os.ReadFile(filepath.Join(dir, "compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	return c, m
}

// TestRealTemplatesPlacement: the fixtures (minimal copies of samba,
// headscale and a clean app), then, with PORTCULLIS_TEMPLATES_DIR, every
// real template: those that must stay on the primary are detected.
func TestRealTemplatesPlacement(t *testing.T) {
	roots := []string{"/srv", "/mnt", "/media"}
	for id, want := range map[string][]string{
		"samba":     {"has a per-person secret option (smb_password)"},
		"headscale": {"is a VPN provider (vpn: block)", "uses host-gateway (gateway)"},
		"echo":      {},
	} {
		c, m := loadFixture(t, filepath.Join("testdata", "placement", id))
		po, reasons := Placement(c, m, nil, roots)
		if po != (len(want) > 0) || !reflect.DeepEqual(reasons, want) {
			t.Errorf("fixture %s: %v %#v, want %#v", id, po, reasons, want)
		}
	}
	dir := os.Getenv("PORTCULLIS_TEMPLATES_DIR")
	if dir == "" {
		t.Skip("PORTCULLIS_TEMPLATES_DIR not set")
	}
	mustPrimary := map[string]string{"samba": "per-person secret", "timemachine": "per-person secret", "headscale": "VPN provider",
		"netbird": "non-HTTP backend scheme", "ai-chat": "AI page", "grafana": "AI companions", "gitea": "AI companions", "scrutiny": "adds the capability SYS_RAWIO"}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var placeable []string
	for _, e := range entries {
		if _, err := os.Stat(filepath.Join(dir, e.Name(), "manifest.yaml")); err != nil {
			continue
		}
		c, m := loadFixture(t, filepath.Join(dir, e.Name()))
		po, reasons := Placement(c, m, nil, roots)
		if want, ok := mustPrimary[e.Name()]; ok && (!po || !strings.Contains(strings.Join(reasons, "\n"), want)) {
			t.Errorf("%s: %v %v, want a %q reason", e.Name(), po, reasons, want)
		}
		for _, r := range reasons {
			if strings.Contains(r, "can't be read") {
				t.Errorf("%s: %s", e.Name(), r)
			}
		}
		if !po {
			placeable = append(placeable, e.Name())
		}
	}
	t.Logf("worker-placeable: %s", strings.Join(placeable, " "))
	if len(placeable) == 0 {
		t.Error("no real template is worker-placeable")
	}
}

// TestLinkNamesReserved (pre-flight P16): link_doc is a core volume and
// portcullis-link* names are core's.
func TestLinkNamesReserved(t *testing.T) {
	for name, c := range map[string]string{
		"link_doc volume":   "services:\n  a:\n    image: x\n    volumes: [link_doc:/l]\nvolumes:\n  link_doc: {}\n",
		"link network":      "services:\n  a:\n    image: x\n    networks: [portcullis-link]\nnetworks:\n  portcullis-link:\n    external: true\n",
		"link-data network": "services:\n  a:\n    image: x\n    networks:\n      mine:\n        aliases: [portcullis-link-data]\nnetworks:\n  mine: {}\n",
	} {
		if err := checkCoreRefs([]byte(c), nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := checkCoreRefs([]byte("services:\n  a:\n    image: x\n    networks:\n      mine:\n        aliases: [portcullis-link-data]\nnetworks:\n  mine: {}\n"), nil); err == nil || !strings.Contains(err.Error(), "link role") {
		t.Errorf("message: %v", err)
	}
}
