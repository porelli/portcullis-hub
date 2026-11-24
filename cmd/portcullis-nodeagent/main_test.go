package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestMainUsage(t *testing.T) {
	for _, c := range []struct {
		args []string
		code int
		err  string
	}{
		{nil, 2, "usage"},
		{[]string{"nope"}, 2, "usage"},
		{[]string{"join", "pcj2.abc"}, 2, "the join code comes on stdin"},
		{[]string{"checks", "--bogus"}, 2, "usage"},
		{[]string{"serve", "--probes-only"}, 2, "usage"},
		{[]string{"serve", "--probes-only", "--root", "relative"}, 2, "usage"},
		{[]string{"serve", "--root", "/x", "--probes-only"}, 2, "usage"},
		{[]string{"serve", "--bogus"}, 2, "usage"},
		// No state under the root: refused before any listener.
		{[]string{"serve", "--probes-only", "--root", "/nonexistent-nodeagent-root"}, 1, "hasn't joined a cluster"},
	} {
		var out, errb bytes.Buffer
		if got := Main(c.args, strings.NewReader(""), &out, &errb); got != c.code || !strings.Contains(errb.String(), c.err) {
			t.Errorf("%v: %d %q", c.args, got, errb.String())
		}
		if strings.Contains(out.String()+errb.String(), "pcj2.abc") {
			t.Errorf("%v: the code was echoed", c.args)
		}
	}
	var out, errb bytes.Buffer
	if got := Main([]string{"version"}, nil, &out, &errb); got != 0 || out.Len() == 0 {
		t.Errorf("version: %d", got)
	}
	out.Reset()
	if got := Main([]string{"checks", "--dry-run", "--json"}, nil, &out, &errb); got != 0 || !strings.Contains(out.String(), `"class_suggestion"`) {
		t.Errorf("checks --dry-run: %d %s", got, out.String())
	}
}
