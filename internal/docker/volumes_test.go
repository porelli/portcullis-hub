package docker

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// The helper is created hardened and never started; the archive endpoints
// carry the path and the tar body as is.
func TestHelperAndArchive(t *testing.T) {
	var create []byte
	var put struct{ path, body, noOverwrite, copyUIDGID string }
	var calls []string
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_ping" {
			return
		}
		calls = append(calls, r.Method+" "+r.URL.Path)
		switch {
		case r.Method == "POST" && r.URL.Path == "/containers/create":
			create, _ = io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"Id":"h1","Warnings":[]}`))
		case r.Method == "GET" && r.URL.Path == "/containers/h1/archive":
			if r.URL.Query().Get("path") != "/data" {
				t.Errorf("archive path = %q", r.URL.Query().Get("path"))
			}
			w.Header().Set("X-Docker-Container-Path-Stat", "eyJuYW1lIjoiZGF0YSJ9") // {"name":"data"}
			w.Write([]byte("TAR"))
		case r.Method == "PUT" && r.URL.Path == "/containers/h1/archive":
			b, _ := io.ReadAll(r.Body)
			put.path, put.body = r.URL.Query().Get("path"), string(b)
			put.noOverwrite, put.copyUIDGID = r.URL.Query().Get("noOverwriteDirNonDir"), r.URL.Query().Get("copyUIDGID")
		case r.Method == "DELETE" && r.URL.Path == "/containers/h1":
			if r.URL.Query().Get("force") != "1" {
				t.Errorf("remove not forced: %s", r.URL.RawQuery)
			}
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	ctx := context.Background()
	id, err := c.CreateHelper(ctx, HelperSpec{Image: "alpine@sha256:abc", Volumes: map[string]string{"v1": "/data"}, ReadOnly: true, Instance: "x"})
	if err != nil || id != "h1" {
		t.Fatalf("create = %q, %v", id, err)
	}
	var cfg struct {
		Image, User     string
		Entrypoint      []string
		NetworkDisabled bool
		Labels          map[string]string
	}
	var hc struct {
		NetworkMode    string
		ReadonlyRootfs bool
		CapDrop        []string
		SecurityOpt    []string
		Privileged     bool
		Binds          []string
		Mounts         []struct {
			Type, Source, Target string
			ReadOnly             bool
			VolumeOptions        struct{ NoCopy bool }
		}
	}
	var top map[string]json.RawMessage
	json.Unmarshal(create, &top)
	json.Unmarshal(create, &cfg) // the config is inline in the create request
	json.Unmarshal(top["HostConfig"], &hc)
	if cfg.Image != "alpine@sha256:abc" || cfg.User != "65534:65534" || !cfg.NetworkDisabled || cfg.Labels[LabelHelper] != "x" {
		t.Errorf("config = %+v", cfg)
	}
	if hc.NetworkMode != "none" || !hc.ReadonlyRootfs || len(hc.CapDrop) != 1 || hc.CapDrop[0] != "ALL" ||
		len(hc.SecurityOpt) != 1 || hc.SecurityOpt[0] != "no-new-privileges:true" || hc.Privileged || len(hc.Binds) != 0 {
		t.Errorf("host config = %+v", hc)
	}
	if len(hc.Mounts) != 1 || hc.Mounts[0].Type != "volume" || hc.Mounts[0].Source != "v1" || hc.Mounts[0].Target != "/data" ||
		!hc.Mounts[0].ReadOnly || !hc.Mounts[0].VolumeOptions.NoCopy {
		t.Errorf("mounts = %+v", hc.Mounts)
	}
	rc, err := c.CopyFromContainer(ctx, "h1", "/data")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(rc)
	rc.Close()
	if string(b) != "TAR" {
		t.Errorf("copy from = %q", b)
	}
	if err := c.CopyToContainer(ctx, "h1", "/", strings.NewReader("IN")); err != nil {
		t.Fatal(err)
	}
	if put.path != "/" || put.body != "IN" || put.noOverwrite != "true" || put.copyUIDGID != "" {
		t.Errorf("put = %+v", put)
	}
	if err := c.RemoveContainer(ctx, "h1"); err != nil {
		t.Fatal(err)
	}
	for _, call := range calls {
		if strings.HasSuffix(call, "/start") {
			t.Errorf("helper started: %v", calls)
		}
	}
}
