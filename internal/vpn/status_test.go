package vpn

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const statusDoc = `{"version":1,"written":"2026-11-13T12:00:00Z","mode":"apps","edge":{"ok":true,"error":""},
 "people":{"ok":true,"error":"","public_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","port":51820,"subnet":"10.213.0.0/22","mtu":1280,
           "peers":[{"public_key":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","last_handshake":"2026-11-13T11:59:00Z"},
                    {"public_key":"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=","last_handshake":null}]}}`

func TestReadStatusStale(t *testing.T) {
	p := filepath.Join(t.TempDir(), "status.json")
	os.WriteFile(p, []byte(statusDoc), 0o600)
	at := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	s, err := ReadStatus(p, at.Add(29*time.Second))
	if err != nil || s.People == nil || s.People.Port != 51820 || len(s.Handshakes()) != 1 {
		t.Fatalf("%+v %v", s, err)
	}
	for _, now := range []time.Time{at.Add(31 * time.Second), at.Add(-31 * time.Second)} {
		if _, err := ReadStatus(p, now); !errors.Is(err, ErrStatusStale) {
			t.Errorf("%v: %v", now, err)
		}
	}
	if _, err := ReadStatus(filepath.Join(t.TempDir(), "none"), at); err == nil {
		t.Error("missing file")
	}
	for _, bad := range []string{strings.Replace(statusDoc, `"version":1`, `"version":2`, 1), strings.Replace(statusDoc, `"mode"`, `"x":1,"mode"`, 1), "{"} {
		if _, err := ParseStatus([]byte(bad), at); err == nil {
			t.Errorf("accepted %.40q", bad)
		}
	}
	off, err := ParseStatus([]byte(`{"version":1,"written":"2026-11-13T12:00:00Z","mode":"apps","edge":{"ok":true,"error":""},"people":null}`), at)
	if err != nil || off.People != nil || len(off.Handshakes()) != 0 {
		t.Fatalf("%+v %v", off, err)
	}
}
