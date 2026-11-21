package templates

import (
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
