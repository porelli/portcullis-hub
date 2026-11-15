package agentapi

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"strings"
	"testing"
)

// bundleVector is one entry of testdata/bundle_vectors.json (the agent's
// TestBundleRefusesLinksAndEscapes reads the same file): tar entries in
// order (type reg|dir|symlink|link|char|block|fifo|xglobal), the
// manifest (written as MANIFEST.json, see ManifestMember), the path's
// instance, the cap and the verdict (error: a substring of ReadBundle's).
type bundleVector struct {
	Name     string `json:"name"`
	Instance string `json:"instance"`
	// ManifestMember: first (MANIFEST.json written first, from Manifest
	// or ManifestRaw), second (after the first entry) or missing.
	ManifestMember string `json:"manifest_member"`
	ManifestRaw    string `json:"manifest_raw"`
	Entries        []struct {
		Name     string `json:"name"`
		Type     string `json:"type"`
		Mode     int64  `json:"mode"`
		Data     string `json:"data"`
		Linkname string `json:"linkname"`
	} `json:"entries"`
	Manifest BundleManifest `json:"manifest"`
	MaxBytes int64          `json:"max_bytes"`
	Valid    bool           `json:"valid"`
	Error    string         `json:"error"`
}

var tarTypes = map[string]byte{"reg": tar.TypeReg, "dir": tar.TypeDir, "symlink": tar.TypeSymlink, "link": tar.TypeLink,
	"char": tar.TypeChar, "block": tar.TypeBlock, "fifo": tar.TypeFifo, "xglobal": tar.TypeXGlobalHeader}

func (v bundleVector) tar(t *testing.T) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	manifest := func() {
		if v.ManifestRaw == "" {
			if err := WriteManifest(tw, v.Manifest); err != nil {
				t.Fatal(err)
			}
			return
		}
		tw.WriteHeader(&tar.Header{Name: ManifestName, Typeflag: tar.TypeReg, Mode: 0o600, Size: int64(len(v.ManifestRaw)), Format: tar.FormatPAX})
		tw.Write([]byte(v.ManifestRaw))
	}
	if v.ManifestMember == "first" {
		manifest()
	}
	for i, e := range v.Entries {
		if i == 1 && v.ManifestMember == "second" {
			manifest()
		}
		typ, ok := tarTypes[e.Type]
		if !ok {
			t.Fatalf("%s: type %q", v.Name, e.Type)
		}
		h := &tar.Header{Name: e.Name, Typeflag: typ, Mode: e.Mode, Linkname: e.Linkname, Format: tar.FormatPAX}
		if typ == tar.TypeReg {
			h.Size = int64(len(e.Data))
		}
		if typ == tar.TypeXGlobalHeader {
			h = &tar.Header{Typeflag: typ, PAXRecords: map[string]string{"comment": "x"}, Format: tar.FormatPAX}
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		if typ == tar.TypeReg {
			tw.Write([]byte(e.Data))
		}
	}
	tw.Close()
	return buf.Bytes()
}

func loadBundleVectors(t *testing.T) []bundleVector {
	b, err := os.ReadFile("testdata/bundle_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []bundleVector
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&vs); err != nil {
		t.Fatal(err)
	}
	return vs
}

func TestBundleVectors(t *testing.T) {
	vs := loadBundleVectors(t)
	if len(vs) < 25 {
		t.Fatalf("%d vectors", len(vs))
	}
	for _, v := range vs {
		got := map[string]string{}
		modes := map[string]fs.FileMode{}
		_, err := ReadBundle(bytes.NewReader(v.tar(t)), v.Instance, v.MaxBytes, func(name string, mode fs.FileMode, r io.Reader) error {
			b, err := io.ReadAll(r)
			if err != nil {
				return err // a staging writer drops the file
			}
			got[name], modes[name] = string(b), mode
			return nil
		})
		if !v.Valid {
			if err == nil || !strings.Contains(err.Error(), v.Error) {
				t.Errorf("%s: err %v, want %q", v.Name, err, v.Error)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", v.Name, err)
			continue
		}
		if len(got) != len(v.Manifest.Files) {
			t.Errorf("%s: wrote %d files, manifest %d", v.Name, len(got), len(v.Manifest.Files))
		}
		for _, e := range v.Entries {
			if e.Type == "reg" && (got[e.Name] != e.Data || modes[e.Name] != fs.FileMode(e.Mode)) {
				t.Errorf("%s: %s = %q %v", v.Name, e.Name, got[e.Name], modes[e.Name])
			}
		}
	}
}

// TestBundleMismatchNeverEnds: a writer reading a file whose sha256
// differs sees an error, never io.EOF, so it can't commit it; a write
// error is returned as is; a lazy writer's leftovers are still verified.
func TestBundleMismatchNeverEnds(t *testing.T) {
	var v bundleVector
	for _, x := range loadBundleVectors(t) {
		if x.Name == "sha mismatch" {
			v = x
		}
	}
	var sawEOF bool
	_, err := ReadBundle(bytes.NewReader(v.tar(t)), v.Instance, v.MaxBytes, func(name string, _ fs.FileMode, r io.Reader) error {
		if name != "env" {
			return nil // lazy: never reads
		}
		buf := make([]byte, 1)
		for {
			_, err := r.Read(buf)
			if err == io.EOF {
				sawEOF = true
			}
			if err != nil {
				return err
			}
		}
	})
	if sawEOF || err == nil || !strings.Contains(err.Error(), "sha256 differs") {
		t.Errorf("eof %v err %v", sawEOF, err)
	}
	boom := errors.New("disk full")
	for _, x := range loadBundleVectors(t) {
		if x.Name == "clean bundle" {
			v = x
		}
	}
	if _, err := ReadBundle(bytes.NewReader(v.tar(t)), v.Instance, v.MaxBytes, func(string, fs.FileMode, io.Reader) error { return boom }); !errors.Is(err, boom) {
		t.Errorf("write error: %v", err)
	}
}
