package hub

import (
	"path/filepath"
	"strings"
	"testing"
)

// Every template: an absolute bind source at, inside or above the core
// checkout's host path (ProjectHostDir, compose's --project-directory)
// keeps the template out of the catalog, whatever its mode; others load.
func TestTemplateBindNearCoreCheckoutRefused(t *testing.T) {
	for _, c := range []struct {
		vol     string
		refused bool
	}{
		{`"/host/project:/core:ro"`, true},
		{`"/host/project/templates:/t:ro"`, true},
		{`"/host/project/data/x:/x"`, true},
		{`"/host:/h:ro"`, true},
		{`"/:/root:ro"`, true},
		{`"/HOST/Project/:/c"`, true},
		{`"/host/project/../project/x:/x"`, true},
		{`{type: bind, source: /host/project/certs, target: /c, read_only: true}`, true},
		{`"${CORE_DIR:-/host/project}:/c"`, true},
		{`"/host/projectx:/x"`, false},
		{`"/srv/data:/d"`, false},
		{`"./conf:/conf:ro"`, false},
		{`"data:/data"`, false},
	} {
		f := newFixture(t)
		comp := strings.Replace(grafanaCompose, "    image: grafana\n", "    image: grafana\n    volumes:\n      - "+c.vol+"\n", 1)
		writeFile(t, filepath.Join(f.src, "grafana", "compose.yml"), comp)
		f.h.Discover()
		if loaded := f.h.Template("grafana") != nil; loaded == c.refused {
			t.Errorf("%s: loaded %v, want refused %v", c.vol, loaded, c.refused)
		}
	}
}
