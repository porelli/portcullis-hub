package hub

import (
	"path/filepath"
	"testing"

	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/templates"
)

// TestSMBFixtureLoads: testdata/settings/smbfixture (file sharing, F24:
// a router-less custom template with person_secret, person_id,
// requires_any, a tsv people file and a sync hook) passes the
// validator with the Hub's registry. Later tasks build on it.
func TestSMBFixtureLoads(t *testing.T) {
	tm, err := templates.Load(filepath.Join("testdata", "settings"), "smbfixture", "src", "example.org", settings.NewRegistry())
	if err != nil {
		t.Fatalf("smbfixture refused: %v", err)
	}
	m := &tm.Manifest
	if !m.Routerless() {
		t.Error("Routerless() = false")
	}
	types := map[string]string{}
	for _, o := range m.Options() {
		types[o.Key] = o.Type
	}
	if types["share_password"] != templates.TypePersonSecret || types["uid"] != templates.TypePersonID {
		t.Errorf("options = %v", types)
	}
	if len(m.Files) != 1 || m.Files[0].Format != templates.FormatTSV {
		t.Errorf("files = %+v", m.Files)
	}
}
