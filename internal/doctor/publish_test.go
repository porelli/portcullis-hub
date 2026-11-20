package doctor

import (
	"strings"
	"testing"
	"time"
)

// The published-document kinds (contract §14.5): silent without input,
// each names the document (and the pods).
func TestPublishedKinds(t *testing.T) {
	run := func(in *PublishedIn) []Finding {
		var out []Finding
		for _, k := range PublishedKinds {
			out = append(out, publishedCheck{kind: k}.Run(&Inputs{Published: in})...)
		}
		return out
	}
	if f := run(nil); len(f) != 0 {
		t.Errorf("nil: %v", f)
	}
	f := run(&PublishedIn{TooLarge: []PublishedTooLargeIn{{Doc: "group-gate-policy", Size: 1_000_001}},
		Stale: []PublishedStaleIn{{Doc: "vpn", Rev: "0123456789abcdef", Since: time.Unix(0, 0), Pods: []string{"wg-1"}}}})
	if len(f) != 2 || f[0].Kind != KindPublishedDocTooLarge || !strings.Contains(f[0].Title, "group-gate-policy") || !strings.Contains(f[0].Title, "1000001") ||
		f[1].Kind != KindPublishedDocStale || !strings.Contains(f[1].Why, "wg-1") || f[0].Severity != Problem || f[1].Severity != Problem {
		t.Errorf("%+v", f)
	}
	f = run(&PublishedIn{CopyFailed: []PublishedCopyIn{{Doc: "mcp-credentials", Err: "no space left on device"}}})
	if len(f) != 1 || f[0].Kind != KindPublishedDocStale || !strings.Contains(f[0].Title, "own copy of mcp-credentials") || !strings.Contains(f[0].Why, "no space") {
		t.Errorf("copy failed: %+v", f)
	}
}
