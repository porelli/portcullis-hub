package main

import (
	"bytes"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestHubHAChecklist: `hub ha checklist` prints GET /host/ha's answer;
// a refusal (Docker: 404, or the page's 409) is the text on stderr and 1;
// anything else is usage (2).
func TestHubHAChecklist(t *testing.T) {
	dir, err := os.MkdirTemp("", "ha")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "s.sock")
	var stdout, stderr bytes.Buffer
	if code := haMain([]string{"checklist"}, &stdout, &stderr, sock); code != 1 || !strings.Contains(stderr.String(), "the Hub isn't running") {
		t.Fatalf("no socket: %d %q", code, stderr.String())
	}
	for _, bad := range [][]string{nil, {"enable"}, {"checklist", "x"}} {
		if code := haMain(bad, &stdout, &stderr, sock); code != 2 {
			t.Errorf("%v: %d", bad, code)
		}
	}
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	refuse := false
	var paths []string
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		if refuse {
			http.Error(w, "high availability needs Kubernetes", 409)
			return
		}
		w.Write([]byte(`{"experimental":true,"command":"./portcullis ha enable"}`))
	})}
	go srv.Serve(l)
	defer srv.Close()
	stdout.Reset()
	stderr.Reset()
	if code := haMain([]string{"checklist"}, &stdout, &stderr, sock); code != 0 || stdout.String() != `{"experimental":true,"command":"./portcullis ha enable"}` {
		t.Errorf("checklist: %d %q %q", code, stdout.String(), stderr.String())
	}
	refuse = true
	stdout.Reset()
	if code := haMain([]string{"checklist"}, &stdout, &stderr, sock); code != 1 || !strings.Contains(stderr.String(), "needs Kubernetes") || stdout.Len() != 0 {
		t.Errorf("refused: %d %q", code, stderr.String())
	}
	if strings.Join(paths, "|") != "GET /host/ha|GET /host/ha" {
		t.Errorf("requests %q", paths)
	}
}
