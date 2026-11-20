package publish

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/jsonstrict"
)

// publishedDoc is one row of published_docs.json (contract §4 "On
// Kubernetes: published documents"; byte-copied to core
// tests/published_docs.json).
type publishedDoc struct {
	Doc     string                   `json:"doc"`
	Object  string                   `json:"object"`
	Kind    string                   `json:"kind"`
	Key     string                   `json:"key"`
	Mount   string                   `json:"mount"`
	Readers []string                 `json:"readers"`
	Mode    string                   `json:"mode"`
	FSGroup jsonstrict.Nullable[int] `json:"fs_group"`
	RevPath string                   `json:"rev_path"`
}

// TestPublishedDocsVectorsShape: the file decodes strictly and holds
// exactly the eight rows of the contract's table.
func TestPublishedDocsVectorsShape(t *testing.T) {
	b, err := os.ReadFile("testdata/published_docs.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []publishedDoc
	if err := jsonstrict.Decode(b, &rows); err != nil {
		t.Fatal(err)
	}
	want := map[string]struct{ object, kind, mount, readers string }{
		"group-gate-policy.json": {"pub-group-gate-policy", "configmap", "/hub-data", "group-gate"},
		"user-attributes.json":   {"pub-user-attributes", "configmap", "/hub-data", "group-gate"},
		"portal-apps.json":       {"pub-portal-apps", "configmap", "/hub-data", "group-gate"},
		"signin-keycloak.json":   {"pub-signin-keycloak", "configmap", "/hub-data", "keycloak"},
		"impersonation.json":     {"pub-impersonation", "configmap", "/hub-data", "group-gate keycloak"},
		"mcp-gate.json":          {"pub-mcp-gate", "configmap", "/hub-data", "mcp-gate"},
		"mcp-credentials.json":   {"pub-mcp-credentials", "secret", "/hub-data", "mcp-gate"},
		"vpn.json":               {"pub-vpn", "configmap", "/vpn-doc", "group-gate wg"},
	}
	if len(rows) != len(want) {
		t.Fatalf("%d rows, want %d", len(rows), len(want))
	}
	seen := map[string]bool{}
	for _, r := range rows {
		w, ok := want[r.Key]
		if !ok || seen[r.Key] {
			t.Errorf("unexpected or repeated key %q", r.Key)
			continue
		}
		seen[r.Key] = true
		if r.Object != w.object || r.Kind != w.kind || r.Mount != w.mount || strings.Join(r.Readers, " ") != w.readers {
			t.Errorf("%s: %+v, want %+v", r.Key, r, w)
		}
		if !slices.IsSorted(r.Readers) {
			t.Errorf("%s: readers %v not sorted", r.Key, r.Readers)
		}
		if r.Doc != strings.TrimSuffix(r.Key, ".json") || r.RevPath != r.Mount+"/.rev-"+r.Doc {
			t.Errorf("%s: doc %q, rev_path %q", r.Key, r.Doc, r.RevPath)
		}
		switch r.Kind {
		case "configmap":
			if r.Mode != "0444" || r.FSGroup.Valid {
				t.Errorf("%s: a ConfigMap projects 0444 with fs_group null, got %s %+v", r.Key, r.Mode, r.FSGroup)
			}
		case "secret":
			if r.Mode != "0440" || !r.FSGroup.Valid || r.FSGroup.V != 10001 {
				t.Errorf("%s: the Secret projects 0440 for fs_group 10001, got %s %+v", r.Key, r.Mode, r.FSGroup)
			}
		}
	}
}
