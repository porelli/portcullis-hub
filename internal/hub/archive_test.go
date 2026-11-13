package hub

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/docker"
)

type tEntry struct {
	name, link string
	typ        byte
	body       string
}

func mkTar(t *testing.T, es ...tEntry) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	var patch []int // offsets of headers whose type is set after writing
	var patchTyp []byte
	for _, e := range es {
		typ := e.typ
		if typ != tar.TypeDir && strings.HasSuffix(e.name, "/") {
			// archive/tar refuses to write a non-directory named "…/":
			// written as a directory, its type byte patched below.
			tw.Flush()
			patch, patchTyp = append(patch, b.Len()), append(patchTyp, typ)
			typ = tar.TypeDir
		}
		hdr := &tar.Header{Name: e.name, Typeflag: typ, Mode: 0o644, Linkname: e.link, Size: int64(len(e.body)), Uid: 472, Gid: 0, Format: tar.FormatUSTAR}
		if typ == tar.TypeDir {
			hdr.Mode = 0o755
		}
		if typ != tar.TypeReg {
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if hdr.Size > 0 {
			tw.Write([]byte(e.body))
		}
	}
	tw.Close()
	out := b.Bytes()
	for i, off := range patch {
		h := out[off : off+512]
		h[156] = patchTyp[i]
		copy(h[148:156], "        ")
		sum := 0
		for _, c := range h {
			sum += int(c)
		}
		copy(h[148:156], []byte(fmt.Sprintf("%06o\x00 ", sum)))
	}
	return out
}

// readTar lists an archive as "name|type|link|uid|body".
func readTar(t *testing.T, b []byte) []string {
	t.Helper()
	var out []string
	tr := tar.NewReader(bytes.NewReader(b))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(tr)
		out = append(out, strings.Join([]string{hdr.Name, string(hdr.Typeflag), hdr.Linkname, string(rune('0' + hdr.Uid%10)), string(body)}, "|"))
	}
}

// Docker's shape and Podman's (root "/", children "/x", hard links "/x")
// normalise to the same canonical archive.
func TestNormalizeArchiveDockerAndPodman(t *testing.T) {
	docker := mkTar(t,
		tEntry{name: "data/", typ: tar.TypeDir},
		tEntry{name: "data/grafana.db", typ: tar.TypeReg, body: "v1"},
		tEntry{name: "data/plugins/", typ: tar.TypeDir},
		tEntry{name: "data/plugins/p", typ: tar.TypeReg, body: "p"},
		tEntry{name: "data/hard", typ: tar.TypeLink, link: "data/grafana.db"},
		tEntry{name: "data/sym", typ: tar.TypeSymlink, link: "/etc/passwd"},
	)
	podman := mkTar(t,
		tEntry{name: "/", typ: tar.TypeDir},
		tEntry{name: "/grafana.db", typ: tar.TypeReg, body: "v1"},
		tEntry{name: "/plugins/", typ: tar.TypeDir},
		tEntry{name: "/plugins/p", typ: tar.TypeReg, body: "p"},
		tEntry{name: "/hard", typ: tar.TypeLink, link: "/grafana.db"},
		tEntry{name: "/sym", typ: tar.TypeSymlink, link: "/etc/passwd"},
	)
	dot := mkTar(t,
		tEntry{name: "./", typ: tar.TypeDir},
		tEntry{name: "./grafana.db", typ: tar.TypeReg, body: "v1"},
		tEntry{name: "./plugins/", typ: tar.TypeDir},
		tEntry{name: "./plugins/p", typ: tar.TypeReg, body: "p"},
		tEntry{name: "./hard", typ: tar.TypeLink, link: "./grafana.db"},
		tEntry{name: "./sym", typ: tar.TypeSymlink, link: "/etc/passwd"},
	)
	var outs [][]string
	for name, in := range map[string][]byte{"docker": docker, "podman": podman, "dot": dot} {
		var out bytes.Buffer
		if err := normalizeArchive(bytes.NewReader(in), &out, helperMount, checkVolumeType); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := checkVolumeArchiveBytes(out.Bytes()); err != nil {
			t.Fatalf("%s: canonical archive refused: %v", name, err)
		}
		outs = append(outs, readTar(t, out.Bytes()))
	}
	want := []string{"data/|5||2|", "data/grafana.db|0||2|v1", "data/plugins/|5||2|", "data/plugins/p|0||2|p", "data/hard|1|data/grafana.db|2|", "data/sym|2|/etc/passwd|2|"}
	for _, o := range outs {
		if !reflect.DeepEqual(o, want) {
			t.Errorf("normalised:\n got %q\nwant %q", o, want)
		}
	}
	// And back, relative to the mount: "./", "./x", hard links "./x".
	var canon, rel bytes.Buffer
	normalizeArchive(bytes.NewReader(podman), &canon, helperMount, nil)
	if err := relativeArchive(bytes.NewReader(canon.Bytes()), &rel, helperMount); err != nil {
		t.Fatal(err)
	}
	if got, want := readTar(t, rel.Bytes()), []string{"./|5||2|", "./grafana.db|0||2|v1", "./plugins/|5||2|", "./plugins/p|0||2|p", "./hard|1|./grafana.db|2|", "./sym|2|/etc/passwd|2|"}; !reflect.DeepEqual(got, want) {
		t.Errorf("relative:\n got %q\nwant %q", got, want)
	}
}

func checkVolumeArchiveBytes(b []byte) error {
	tr := tar.NewReader(bytes.NewReader(b))
	an := newArchiveNames(helperMount)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if err := checkVolumeEntry(an, hdr); err != nil {
			return err
		}
	}
}

// Everything else stays refused.
func TestNormalizeArchiveRefusals(t *testing.T) {
	root := tEntry{name: "/", typ: tar.TypeDir}
	for name, es := range map[string][]tEntry{
		"absolute file first":          {{name: "/etc/passwd", typ: tar.TypeReg, body: "x"}},
		"root as a regular file":       {{name: "/", typ: tar.TypeReg, body: "x"}},
		"dot root as a file":           {{name: "./", typ: tar.TypeReg}},
		"dot-dot":                      {root, {name: "/../x", typ: tar.TypeReg}},
		"relative dot-dot":             {{name: "data/", typ: tar.TypeDir}, {name: "data/../x", typ: tar.TypeReg}},
		"leading dot-dot":              {{name: "../x", typ: tar.TypeReg}},
		"duplicate root":               {root, {name: "/", typ: tar.TypeDir}},
		"duplicate docker root":        {{name: "data/", typ: tar.TypeDir}, {name: "./data/", typ: tar.TypeDir}},
		"mixed forms":                  {root, {name: "data/x", typ: tar.TypeReg}},
		"docker then absolute":         {{name: "data/", typ: tar.TypeDir}, {name: "/etc/passwd", typ: tar.TypeReg}},
		"other directory":              {{name: "etc/", typ: tar.TypeDir}},
		"hard link escape":             {root, {name: "/h", typ: tar.TypeLink, link: "/../etc/shadow"}},
		"hard link other form":         {root, {name: "/h", typ: tar.TypeLink, link: "etc/shadow"}},
		"hard link to the root":        {root, {name: "/h", typ: tar.TypeLink, link: "/"}},
		"device":                       {root, {name: "/dev", typ: tar.TypeChar}},
		"no root":                      {},
		"docker entry under a symlink": {{name: "data/", typ: tar.TypeDir}, {name: "data/l", typ: tar.TypeSymlink, link: "../../x"}, {name: "data/l/f", typ: tar.TypeReg, body: "x"}},
		"podman entry under a symlink": {root, {name: "/l", typ: tar.TypeSymlink, link: "/etc"}, {name: "/l/sub/", typ: tar.TypeDir}},
		"dot entry under a symlink":    {{name: "./", typ: tar.TypeDir}, {name: "./l", typ: tar.TypeSymlink, link: "/etc"}, {name: "./l/passwd", typ: tar.TypeReg}},
		"hard link through a symlink":  {root, {name: "/l", typ: tar.TypeSymlink, link: "/etc"}, {name: "/h", typ: tar.TypeLink, link: "/l/shadow"}},
		"hard link to a symlink":       {root, {name: "/l", typ: tar.TypeSymlink, link: "/etc/shadow"}, {name: "/h", typ: tar.TypeLink, link: "/l"}},
		"dot root then absolute":       {{name: "./", typ: tar.TypeDir}, {name: "/x", typ: tar.TypeReg}},
	} {
		var out bytes.Buffer
		if err := normalizeArchive(bytes.NewReader(mkTar(t, es...)), &out, helperMount, checkVolumeType); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A stored archive must be in the Hub's form.
	if err := checkVolumeArchiveBytes(mkTar(t, tEntry{name: "/", typ: tar.TypeDir})); err == nil {
		t.Error("a stored archive in Podman's form accepted")
	}
}

// The fixer's snapshot transfer reads both engines' forms of /out.
func TestReadSnapshotTarForms(t *testing.T) {
	for name, es := range map[string][]tEntry{
		"docker": {{name: "out/", typ: tar.TypeDir}, {name: "out/snapshot.ndjson.gz", typ: tar.TypeReg, body: "snap"}},
		"podman": {{name: "/", typ: tar.TypeDir}, {name: "/snapshot.ndjson.gz", typ: tar.TypeReg, body: "snap"}},
	} {
		var got string
		err := readSnapshotTar(bytes.NewReader(mkTar(t, es...)), func(r io.Reader) error {
			b, _ := io.ReadAll(r)
			got = string(b)
			return nil
		})
		if err != nil || got != "snap" {
			t.Errorf("%s: %q, %v", name, got, err)
		}
	}
	for name, es := range map[string][]tEntry{
		"absolute outside": {{name: "/etc/passwd", typ: tar.TypeReg, body: "x"}},
		"root as a file":   {{name: "/", typ: tar.TypeReg}},
		"dot-dot":          {{name: "/", typ: tar.TypeDir}, {name: "/../snapshot.ndjson.gz", typ: tar.TypeReg}},
		"duplicate root":   {{name: "/", typ: tar.TypeDir}, {name: "/", typ: tar.TypeDir}},
		"two snapshots":    {{name: "/", typ: tar.TypeDir}, {name: "/snapshot.ndjson.gz", typ: tar.TypeReg}, {name: "/snapshot.ndjson.gz", typ: tar.TypeReg}},
		"another file":     {{name: "/", typ: tar.TypeDir}, {name: "/x", typ: tar.TypeReg}},
		"snapshot symlink": {{name: "/", typ: tar.TypeDir}, {name: "/snapshot.ndjson.gz", typ: tar.TypeSymlink, link: "/etc/shadow"}},
	} {
		if err := readSnapshotTar(bytes.NewReader(mkTar(t, es...)), func(io.Reader) error { return nil }); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Under Podman (its archive shape, an extract reaching a volume only at
// its mount) a backup stores the same canonical archive as under Docker,
// and a restore fills the volume (extract at /data, names relative).
func TestBackupRestorePodmanArchives(t *testing.T) {
	f, _, _ := grafanaB(t)
	f.h.cfg.Runtime = docker.RuntimePodman
	ve := f.engine.vol()
	ve.vmu.Lock()
	ve.podman = true
	ve.vmu.Unlock()
	entry, err := f.h.BackupInstance("grafana-b", directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	_, data, _ := readArchive(t, archivePath(f, entry.Archive))
	inner := innerTar(t, data["volumes/grafana-data.tar"])
	if h := inner["data/grafana.db"]; h == nil || h.Uid != 472 || h.Mode != 0640 {
		t.Errorf("grafana.db = %+v (%v)", h, inner)
	}
	if h := inner["data/"]; h == nil || h.Typeflag != tar.TypeDir || h.Uid != 472 {
		t.Errorf("volume root = %+v", h)
	}
	for n := range inner {
		if strings.HasPrefix(n, "/") {
			t.Errorf("stored entry %q in Podman's form", n)
		}
	}
	putFiles(f, "portcullis_grafana-b-grafana-data", fakeFile{Name: "grafana.db", Mode: 0600, UID: 1, Body: "v2"}, fakeFile{Name: "junk", Body: "j"})
	if _, err := f.h.RestoreInstance("grafana-b", entry.Archive, directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	files := f.engine.volumeFiles("portcullis_grafana-b-grafana-data")
	if files["grafana.db"].Body != "v1" || files["grafana.db"].UID != 472 || files["grafana.db"].Mode != 0640 || files[""].UID != 472 {
		t.Errorf("volume = %+v", files)
	}
	if _, junk := files["junk"]; junk {
		t.Error("the volume was merged, not replaced")
	}
}
