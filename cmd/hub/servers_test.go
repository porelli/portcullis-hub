package main

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestHubServersSubcommand: `hub servers …` is a thin client of the
// running Hub's socket (P19): the add request comes on stdin, the code is
// printed alone on stdout (the rest on stderr), nothing but the
// subcommand and an id is on argv; a refusal exits 1 with the Hub's text.
func TestHubServersSubcommand(t *testing.T) {
	dir, err := os.MkdirTemp("", "hs")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "s.sock")
	var stdout, stderr bytes.Buffer
	if code := serversMain([]string{"list"}, nil, &stdout, &stderr, sock); code != 1 || !strings.Contains(stderr.String(), "the Hub isn't running") {
		t.Fatalf("no socket: %d %q", code, stderr.String())
	}
	for _, bad := range [][]string{nil, {"nope"}, {"add-cluster-node", "pcj2.x"}, {"remove"}, {"revoke", "Bad!"}} {
		if code := serversMain(bad, strings.NewReader(`{}`), &stdout, &stderr, sock); code != 2 {
			t.Errorf("%v: %d", bad, code)
		}
	}
	if code := serversMain([]string{"add-cluster-node"}, strings.NewReader(`not json`), &stdout, &stderr, sock); code != 2 {
		t.Errorf("a bad body: %d", code)
	}
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = append(got, r.Method+" "+r.URL.Path+" "+string(b))
		switch r.URL.Path {
		case "/host/servers/cluster-node":
			w.WriteHeader(201)
			w.Write([]byte(`{"code":"pcj2.SECRET","role":"server","notice":"Joining as a server gives this machine full control of the cluster (cluster-admin).","command":"curl -fsSL https://example.org/node/join.sh | sudo sh"}`))
		case "/host/servers/n3/remove":
			http.Error(w, "removing n3 would leave fewer than 3 servers", 409)
		default:
			w.Write([]byte(`{"servers":[]}`))
		}
	})}
	go srv.Serve(l)
	defer srv.Close()
	stdout.Reset()
	stderr.Reset()
	if code := serversMain([]string{"add-cluster-node"}, strings.NewReader(`{"id":"n4","role":"server"}`), &stdout, &stderr, sock); code != 0 {
		t.Fatalf("add: %d %q", code, stderr.String())
	}
	if stdout.String() != "pcj2.SECRET\n" || strings.Contains(stderr.String(), "SECRET") || !strings.Contains(stderr.String(), "cluster-admin") {
		t.Errorf("stdout %q stderr %q", stdout.String(), stderr.String())
	}
	stderr.Reset()
	if code := serversMain([]string{"remove", "n3"}, strings.NewReader(`{"confirm":"n3"}`), &stdout, &stderr, sock); code != 1 || !strings.Contains(stderr.String(), "fewer than 3 servers") {
		t.Errorf("remove: %d %q", code, stderr.String())
	}
	if code := serversMain([]string{"list"}, nil, &stdout, &stderr, sock); code != 0 {
		t.Errorf("list: %d", code)
	}
	want := []string{`POST /host/servers/cluster-node {"id":"n4","role":"server"}`, `POST /host/servers/n3/remove {"confirm":"n3"}`, `GET /host/servers `}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("requests %q", got)
	}
}

// TestNodeadmURLFromEnv: unset is the default; only an https origin.
func TestNodeadmURLFromEnv(t *testing.T) {
	env := func(v string) func(string) string { return func(string) string { return v } }
	if u, err := nodeadmURLFromEnv(env("")); err != nil || u != "https://nodeadm.portcullis-nodeadm.svc:8443" {
		t.Errorf("default %q %v", u, err)
	}
	for _, bad := range []string{"http://x:8443", "https://u:p@x", "https://x/v1", "https://x?a=b", "nodeadm:8443"} {
		if _, err := nodeadmURLFromEnv(env(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
