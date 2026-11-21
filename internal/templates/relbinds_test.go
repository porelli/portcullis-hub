package templates

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCheckRelativeBinds (ux2 R2-M2): a template's relative binds are
// only its own files or the CA bundle — never ../, another instance's
// appfiles (the mail admin view's ticket key included), secrets/, another
// template's files, or a symlink out of its directory.
func TestCheckRelativeBinds(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "conf"), 0o755)
	os.WriteFile(filepath.Join(dir, "conf", "ok.conf"), []byte("x"), 0o644)
	outside := t.TempDir()
	os.Symlink(outside, filepath.Join(dir, "escape"))
	os.Symlink(filepath.Join(dir, "conf"), filepath.Join(dir, "inside"))
	svc := func(vol string) []byte {
		return []byte("services:\n  web:\n    image: x\n    volumes:\n      - " + vol + "\n")
	}
	for _, ok := range []string{
		"./templates/app/conf/ok.conf:/etc/ok.conf:ro", "./templates/app:/t:ro", "./certs/ca-bundle.crt:/ca.crt:ro",
		"./templates/app/inside:/i:ro", "data:/data", "/srv/media:/media:ro", "./templates/app/x/../conf:/c:ro",
	} {
		if err := CheckRelativeBinds(dir, "app", svc(ok)); err != nil {
			t.Errorf("%s refused: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"./appfiles/stalwart/mail-admin:/x:ro", "./appfiles/other/settings:/s:ro", "./appfiles/app/x:/x:ro", "./secrets:/s:ro",
		"./templates/other/gate:/g", "./templates/app/../other:/o:ro", "../etc:/e:ro", "./templates/app/../../secrets:/s:ro",
		"./.env:/e:ro", "./:/project:ro", ".:/project", "./certs:/c:ro", "./templates/app/escape:/x:ro", "./templates/app/escape/y:/x:ro",
		"./templates/${APP}:/x:ro", "./templates/apps:/x:ro",
	} {
		if err := CheckRelativeBinds(dir, "app", svc(bad)); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	// One unresolvable entry never hides the next.
	two := []byte("services:\n  web:\n    image: x\n    volumes:\n      - ~/a:/a\n      - ./secrets:/s:ro\n")
	if err := CheckRelativeBinds(dir, "app", two); err == nil {
		t.Error("a bind after an unresolvable entry accepted")
	}
	// No interpolation in any mount, of any form, in either syntax (the
	// R2-M2 follow-up ruling): compose would resolve it after the checks.
	for _, src := range []string{
		"$X", "${X}", "${X:-./appfiles/other}", "${X-./secrets}", "${X:?err}", "$X/..", "./templates/app/$X", "./templates/app/${X:-../../secrets}",
		"/srv/${X}", "$$X", "${X:-/srv/media}",
	} {
		for name, compose := range map[string]string{
			"short": "      - \"" + src + ":/x:ro\"\n",
			"long":  "      - {type: bind, source: \"" + src + "\", target: /x}\n",
		} {
			err := CheckRelativeBinds(dir, "app", []byte("services:\n  web:\n    image: x\n    volumes:\n"+compose))
			if err == nil || !strings.Contains(err.Error(), "can't be interpolated") {
				t.Errorf("%s %s: %v", name, src, err)
			}
		}
	}
	for _, c := range []string{
		"      - \"data:/x/${X}\"\n",                                   // short syntax: anywhere in the entry
		"      - {type: \"${T}\", source: /etc, target: /x}\n",         // an interpolated type
		"      - {type: volume, source: \"${V:-data}\", target: /x}\n", // a named volume too
	} {
		if err := CheckRelativeBinds(dir, "app", []byte("services:\n  web:\n    image: x\n    volumes:\n"+c)); err == nil || !strings.Contains(err.Error(), "can't be interpolated") {
			t.Errorf("%q: %v", c, err)
		}
	}
	long := []byte("services:\n  web:\n    image: x\n    volumes:\n      - {type: bind, source: ./appfiles/stalwart/mail-admin, target: /x, read_only: true}\n")
	if err := CheckRelativeBinds(dir, "app", long); err == nil || !strings.Contains(err.Error(), "its own files") {
		t.Errorf("long syntax: %v", err)
	}
}

// Round 4: a source that isn't absolute is relative, "./" or not; "~" is
// refused; the CA bundle only read-only; an entry the check can't read is
// an error (fail closed); top-level volume drivers are refused.
func TestCheckRelativeBindsRound4(t *testing.T) {
	dir := t.TempDir()
	run := func(vols string) error {
		return CheckRelativeBinds(dir, "app", []byte("services:\n  web:\n    image: x\n    volumes:\n"+vols))
	}
	for _, c := range []struct{ vols, want string }{
		{"      - {type: bind, source: appfiles/stalwart/mail-admin, target: /x, read_only: true}\n", "its own files"},
		{"      - appfiles/x:/y:ro\n", "its own files"},
		{"      - secrets/a:/y:ro\n", "its own files"},
		{"      - {type: bind, source: templates/app/../other, target: /x}\n", "its own files"},
		{"      - ~/x:/y:ro\n", "can't start with ~"},
		{"      - {type: bind, source: ~/x, target: /y}\n", "can't start with ~"},
		{"      - ./certs/ca-bundle.crt:/ca.crt\n", "must be bound read-only"},
		{"      - {type: bind, source: ./certs/ca-bundle.crt, target: /ca.crt}\n", "must be bound read-only"},
		{"      - ./certs/ca-bundle.crt:/ca.crt:rw\n", "must be bound read-only"},
		{"      - ./certs/ca-bundle.crt:/ca.crt:ro,rw\n", "both ro and rw"},
		{"      - ./certs/ca-bundle.crt:/ca.crt:rw,ro\n", "both ro and rw"},
		{"      - ./templates/app/conf:/c:ro,rw\n", "both ro and rw"},
		{"      - data:/d:rw,ro\n", "both ro and rw"},
		{"      - {type: bind, source: ./certs/ca-bundle.crt, target: /ca.crt, read_only: \"true\"}\n", "must be bound read-only"},
		{"      - {type: bind, source: ./certs/ca-bundle.crt, target: /ca.crt, read_only: yes}\n", "must be bound read-only"},
		{"      - a:b:c:d\n", "not source:target"},
		{"      - {type: npipe, source: x, target: /y}\n", "isn't supported"},
		{"      - {type: bind, target: /y}\n", "needs a source"},
		{"      - {type: volume, source: a/b, target: /y}\n", "volume name"},
		{"      - 'bad name!:/y'\n", "neither a path nor a volume name"},
		{"      - relative\n", "anonymous volume"},
		{"      - 42\n", "string or a mapping"},
	} {
		if err := run(c.vols); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: %v, want %q", c.vols, err, c.want)
		}
	}
	for _, ok := range []string{
		"      - templates/app/conf:/c:ro\n", "      - {type: bind, source: templates/app, target: /t, read_only: true}\n",
		"      - ./certs/ca-bundle.crt:/ca.crt:ro\n", "      - {type: bind, source: ./certs/ca-bundle.crt, target: /ca.crt, read_only: true}\n",
		"      - data:/data\n", "      - /data\n", "      - {type: tmpfs, target: /tmp}\n", "      - {type: volume, source: data, target: /d}\n",
	} {
		if err := run(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, d := range []string{"driver: local", "driver_opts: {type: none, o: bind, device: /etc}"} {
		c := "services:\n  web:\n    image: x\n    volumes:\n      - data:/d\nvolumes:\n  data:\n    " + d + "\n"
		if err := CheckRelativeBinds(dir, "app", []byte(c)); err == nil || !strings.Contains(err.Error(), "volume data sets driver") {
			t.Errorf("%s: %v", d, err)
		}
	}
	if err := CheckRelativeBinds(dir, "app", []byte("services:\n  web:\n    image: x\nvolumes:\n  data: {labels: {a: b}}\n  other:\n")); err != nil {
		t.Errorf("plain volumes refused: %v", err)
	}
}

// TestRelBindVectors: the shared vectors (testdata/relbind_vectors.json,
// byte-identical to the templates repo's tests/relbind_vectors.json):
// whitespace and control characters (R3-I1), the CA bundle's options
// (R3-M1), external volumes (N1), a service that isn't a mapping (N2),
// a duplicate key by text (N6).
func TestRelBindVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/relbind_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []struct{ Name, Compose, Want string }
	if err := json.Unmarshal(raw, &vs); err != nil {
		t.Fatal(err)
	}
	for _, v := range vs {
		err := CheckRelativeBinds("", "app", []byte(v.Compose))
		switch {
		case v.Want == "" && err != nil:
			t.Errorf("%s: refused: %v", v.Name, err)
		case v.Want != "" && (err == nil || !strings.Contains(err.Error(), v.Want)):
			t.Errorf("%s: %v, want %q", v.Name, err, v.Want)
		}
	}
}
