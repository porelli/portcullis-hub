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
	// Q8: an answer cut mid-stream, or over the bound: 1, nothing printed.
	refuse = false
	haAnswerMax = 10
	stdout.Reset()
	stderr.Reset()
	if code := haMain([]string{"checklist"}, &stdout, &stderr, sock); code != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "the Hub's answer was cut: over 10 bytes") {
		t.Errorf("over the bound: %d %q %q", code, stdout.String(), stderr.String())
	}
	haAnswerMax = 4 << 20
	if strings.Join(paths, "|") != "GET /host/ha|GET /host/ha|GET /host/ha" {
		t.Errorf("requests %q", paths)
	}
}

// TestHubHAChecklistCutAnswer (Q8): a body cut mid-stream (the
// connection closed before Content-Length) is 1, nothing printed.
func TestHubHAChecklistCutAnswer(t *testing.T) {
	dir, err := os.MkdirTemp("", "ha")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "s.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000")
		w.Write([]byte(`{"experimental":tr`))
		panic(http.ErrAbortHandler) // the connection drops mid-body
	})}
	go srv.Serve(l)
	defer srv.Close()
	var stdout, stderr bytes.Buffer
	if code := haMain([]string{"checklist"}, &stdout, &stderr, sock); code != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "the Hub's answer was cut") {
		t.Errorf("cut: %d %q %q", code, stdout.String(), stderr.String())
	}
}
