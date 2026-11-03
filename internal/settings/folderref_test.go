package settings

import (
	"errors"
	"strings"
	"testing"
)

func TestParseFolderRef(t *testing.T) {
	for in, want := range map[string][2]string{
		"folder:photos":           {"photos", ""},
		"folder:media/movies/hd":  {"media", "movies/hd"},
		"folder:a":                {"a", ""},
		"folder:p-2/My Movies #1": {"p-2", "My Movies #1"},
	} {
		id, sub, ok, err := ParseFolderRef(in)
		if err != nil || !ok || id != want[0] || sub != want[1] {
			t.Errorf("%s = (%q, %q, %v, %v), want %v", in, id, sub, ok, err, want)
		}
	}
	for _, in := range []string{
		"folder:Photos", "folder:p/../x", "folder:p//x", "folder:p/", "folder:p/a:b", "folder:",
		"folder:/x", "folder:p/./x", "folder:p/..", "folder:1p", "folder:p/a\nb", "folder:" + strings.Repeat("a", 32),
		"folder:p/" + strings.Repeat("a", 256), "folder:p_x",
	} {
		if _, _, ok, err := ParseFolderRef(in); err == nil || !ok {
			t.Errorf("%q: ok %v err %v, want a malformed ref", in, ok, err)
		}
	}
	if _, _, ok, err := ParseFolderRef("folder:p/" + strings.Repeat("a", 255)); err != nil || !ok {
		t.Errorf("255-byte subpath: %v", err)
	}
	if _, _, ok, err := ParseFolderRef("/srv/x"); ok || err != nil {
		t.Errorf("/srv/x: ok %v err %v", ok, err)
	}
	if !FolderIDRe.MatchString("a"+strings.Repeat("b", 30)) || FolderIDRe.MatchString("a"+strings.Repeat("b", 31)) {
		t.Error("FolderIDRe length")
	}
}

// Ruling 7 (preflight D10): the path kind keeps refusing refs (fail
// closed for any caller that bypasses the Hub's parseValue).
func TestPathKindRefusesFolderRef(t *testing.T) {
	o := opt(t, pathOpt)
	if _, err := NewRegistry().Parse(o, "folder:photos"); !errors.Is(err, ErrFolderRef) {
		t.Errorf("Parse(ref) = %v, want ErrFolderRef", err)
	}
	k, _ := NewRegistry().Kind("path")
	m := k.(Mounter)
	if _, err := m.HostPath(o, "folder:photos/x"); !errors.Is(err, ErrFolderRef) {
		t.Errorf("HostPath(ref) = %v, want ErrFolderRef", err)
	}
	if p, err := m.HostPath(o, "/srv//x/"); err != nil || p != "/srv/x" {
		t.Errorf("HostPath(plain) = %q, %v", p, err)
	}
	if v := mustParse(t, o, "/srv/x/"); v != "/srv/x" {
		t.Errorf("Parse(plain) = %v", v)
	}
}

// Checks are validated in Registry.CheckOption with the binary-only size
// parser (ruling 9).
func TestChecksFreeSpaceRegistry(t *testing.T) {
	ok := opt(t, pathOpt+"checks: [{kind: free_space, min: 500GiB, reason: big}]\n")
	if err := NewRegistry().CheckOption(ok); err != nil {
		t.Fatal(err)
	}
	for min, part := range map[string]string{"500GB": `min "500GB"`, "lots": `min "lots"`, "0": "more than 0"} {
		wantErr(t, NewRegistry().CheckOption(opt(t, pathOpt+"checks: [{kind: free_space, min: '"+min+"', reason: big}]\n")), "checks[0] (free_space)", part)
	}
}

// The path kind admits a folder block and refuses it next to mode /
// needs (defence in depth: the templates validator refuses it first).
func TestPathKindFolderBlock(t *testing.T) {
	const f = "folder: {access: read, runs_as: {uid: 1, gid: 1}}\n"
	if err := NewRegistry().CheckOption(opt(t, "type: path\ntarget: {service: web, mount: /m}\n"+f)); err != nil {
		t.Fatal(err)
	}
	wantErr(t, NewRegistry().CheckOption(opt(t, pathOpt+f)), "folder.access and folder.runs_as replace them")
	wantErr(t, NewRegistry().CheckOption(opt(t, "type: string\n"+f)), "folder is not a constraint of type string")
}
