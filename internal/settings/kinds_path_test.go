package settings

import (
	"strings"
	"testing"
)

const pathOpt = "type: path\nmode: ro\nneeds: read\ntarget: {service: web, mount: /media}\n"

func TestPathKind(t *testing.T) {
	o := opt(t, pathOpt)
	if err := NewRegistry().CheckOption(o); err != nil {
		t.Fatal(err)
	}
	if v := mustParse(t, o, "/mnt/media/My Movies #1/"); v != "/mnt/media/My Movies #1" {
		t.Errorf("path = %#v", v)
	}
	// ValidatePathSetting rules, plus absolute and not the root.
	refused(t, o, "/mnt/a:b", "':'")
	refused(t, o, "/mnt/a\nb", "control")
	refused(t, o, "relative/dir", "absolute")
	refused(t, o, "/", "/")
	refused(t, o, "/mnt/../..", "/")
	refused(t, o, "folder:abc", "resolved by the Hub")
	refused(t, o, 5, "string")

	k, _ := NewRegistry().Kind("path")
	m, ok := k.(Mounter)
	if !ok {
		t.Fatal("path kind is not a Mounter")
	}
	if p, err := m.HostPath(o, "/mnt//media/./x/"); err != nil || p != "/mnt/media/x" {
		t.Errorf("HostPath = %q, %v", p, err)
	}
	if _, err := m.HostPath(o, "x"); err == nil {
		t.Error("HostPath of a relative path")
	}

	for s, part := range map[string]string{
		"type: path\nmode: rx\n":                    "mode",
		"type: path\nneeds: exec\n":                 "needs",
		"type: path\nmode: ro\nneeds: write\n":      "needs: write",
		"type: path\npattern: '^/mnt/.*$'\n":        "pattern",
		"type: path\nmode: rw\ndefault: relative\n": "default",
	} {
		wantErr(t, NewRegistry().CheckOption(opt(t, s)), part)
	}
	if err := NewRegistry().CheckOption(opt(t, "type: path\nmode: rw\nneeds: write\ndefault: /srv/data\n")); err != nil {
		t.Errorf("rw/write: %v", err)
	}
}

func TestSecretKind(t *testing.T) {
	o := opt(t, "type: secret\ngenerate: {length: 32, charset: ascii_printable}\n")
	if err := NewRegistry().CheckOption(o); err != nil {
		t.Fatal(err)
	}
	if v := mustParse(t, o, "s3cr3t$#\" x"); v != "s3cr3t$#\" x" {
		t.Errorf("secret = %#v", v)
	}
	refused(t, o, "it's", "'")
	refused(t, o, "a\nb", "control")
	refused(t, o, "", "empty")
	refused(t, o, strings.Repeat("a", 4097), "4096")
	if got := NewRegistry().Display(o, "hunter2"); strings.Contains(got, "hunter2") {
		t.Errorf("Display leaks the secret: %q", got)
	}
	wantErr(t, NewRegistry().CheckOption(opt(t, "type: secret\ndefault: abc\n")), "default")
}
