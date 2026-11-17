package api

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDebugRedacts(t *testing.T) {
	var log bytes.Buffer
	var seenAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth = r.Header.Get("Authorization")
		io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"user":"alice","certificates":[],"refused":[],"host_cas":[],"revoked_host_keys":[]}`))
	}))
	defer srv.Close()
	c := &Client{Base: srv.URL, Version: "1.0.0", HTTP: srv.Client(), Debug: &log}
	body := map[string]any{"code": "THE-CODE", "code_verifier": "THE-VERIFIER", "nonce": "THE-NONCE", "key_proof": "-----BEGIN SSH SIGNATURE-----X",
		"redirect_uri": "http://127.0.0.1:38917/callback", "public_key": "ssh-ed25519 AAAA", "host_groups": []string{}}
	var out map[string]any
	if _, err := c.Do(context.Background(), "POST", "/api/cli/v1/ssh/certificates?state=THE-STATE", body, &out, func(r *http.Request, _ []byte) error {
		r.Header.Set("Authorization", "Bearer THE-TOKEN")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"THE-CODE", "THE-VERIFIER", "THE-NONCE", "BEGIN SSH SIGNATURE", "THE-TOKEN", "THE-STATE", "Authorization"} {
		if strings.Contains(log.String(), s) {
			t.Errorf("--debug printed %q: %s", s, log.String())
		}
	}
	if !strings.Contains(log.String(), "> POST") || !strings.Contains(log.String(), "redirect_uri") || seenAuth == "" {
		t.Errorf("debug log %s", log.String())
	}
	if Redact([]byte("not json")) != "[8 bytes]" {
		t.Error("non-JSON")
	}
}

func TestStatusExitCodes(t *testing.T) {
	for code, want := range map[int]int{403: ExitRefused, 409: ExitRefused, 426: ExitError, 500: ExitError, 400: ExitError} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
			w.Write([]byte(`{"error":"why\u001b[2J here"}`))
		}))
		c := &Client{Base: srv.URL, Version: "1.0.0", HTTP: srv.Client()}
		_, err := c.Do(context.Background(), "GET", "/x", nil, nil, nil)
		if ExitCode(err) != want || strings.Contains(err.Error(), "\x1b") {
			t.Errorf("%d: %v (%d)", code, err, ExitCode(err))
		}
		srv.Close()
	}
	c := &Client{Base: "https://127.0.0.1:1", Version: "1", HTTP: http.DefaultClient}
	if _, err := c.Do(context.Background(), "GET", "/x", nil, nil, nil); ExitCode(err) != ExitUnreachable {
		t.Errorf("dial: %v", err)
	}
}

func TestTLSConfigCAFile(t *testing.T) {
	if _, err := TLSConfig("/nonexistent/ca.pem"); err == nil {
		t.Error("a missing CA file accepted")
	}
	tc, err := TLSConfig("")
	if err != nil || tc.InsecureSkipVerify {
		t.Errorf("%v %v", tc, err)
	}
}
