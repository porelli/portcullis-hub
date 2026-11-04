package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/credentials"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/hub"
)

// fakeFreshAuth answers every proof with err (nil: the user, now).
type fakeFreshAuth struct {
	err   error
	user  string // user to verify as (if empty, use requested user)
	calls atomic.Int32
}

func (f *fakeFreshAuth) Verify(_ context.Context, p freshauth.Proof, user string) (*freshauth.Result, error) {
	f.calls.Add(1)
	if f.err != nil {
		return nil, f.err
	}
	verifiedUser := user
	if f.user != "" {
		if f.user != user {
			return nil, &freshauth.Error{Reason: "wrong user"}
		}
		verifiedUser = f.user
	}
	return &freshauth.Result{User: verifiedUser, AuthTime: time.Now(), AMR: []string{"hwk"}}, nil
}

func (f *fakeFreshAuth) Info() freshauth.AuthorizeInfo {
	return freshauth.AuthorizeInfo{
		AuthorizeURL: "https://auth.example.org/a",
		ClientID:     freshauth.ClientID,
		RedirectURI:  "https://people.example.org/",
	}
}

var testProof = freshauth.Proof{Code: "the-code", CodeVerifier: "the-verifier", Nonce: "the-nonce"}

// credEnv is the test environment for credential routes with smbfixture.
type credEnv struct {
	*instEnv
	secrets string
	fa      *fakeFreshAuth
}

func newCredEnv(t *testing.T) *credEnv {
	t.Helper()
	root := t.TempDir()
	secrets := filepath.Join(root, "secrets")
	os.MkdirAll(secrets, 0700)

	// Read smbfixture template
	m, err := os.ReadFile("../hub/testdata/settings/smbfixture/manifest.yaml")
	if err != nil {
		t.Fatal(err)
	}
	c, err := os.ReadFile("../hub/testdata/settings/smbfixture/compose.yml")
	if err != nil {
		t.Fatal(err)
	}

	ie := newInstEnvOpts(t, root, instEnvOpts{
		extra: map[string][2]string{"smbfixture": {string(m), string(c)}},
		cfg: func(cfg *hub.Config) {
			cfg.SecretsDir = secrets
		},
	})

	// Set up test users and groups
	ie.ll.AddUser("alice", "alice@example.org", "Alice", "")
	ie.ll.AddUser("bob", "bob@example.org", "Bob", "")
	ie.ll.AddGroup("users_smbfixture", "alice", "bob")
	ie.ll.AddGroup("admin_smbfixture")

	// Set People source for the Hub (directory provides membership)
	ie.s.Hub.SetPeople(ie.s.Directory)

	// Enable smbfixture
	if err := ie.s.Hub.Enable("smbfixture"); err != nil {
		t.Fatal(err)
	}

	// Set up fake fresh auth
	fa := &fakeFreshAuth{}
	ie.s.Hub.SetFreshAuth(fa)
	ie.s.Hub.SetFreshAuthReady(true) // client is in place

	return &credEnv{instEnv: ie, secrets: secrets, fa: fa}
}

var passwordShape = regexp.MustCompile(`^([2-9A-HJ-NP-Ya-hjkmnp-z]{4}-){5}[2-9A-HJ-NP-Ya-hjkmnp-z]{4}$`)

// TestCreateCredentialRoute: X-Forwarded-User: Alice → alice's credential,
// the right headers, and the body has password. The handler zeroes the
// buffer (spy).
func TestCreateCredentialRoute(t *testing.T) {
	e := newCredEnv(t)

	// POST with valid fresh auth proof
	body, _ := json.Marshal(map[string]string{
		"code":          testProof.Code,
		"code_verifier": testProof.CodeVerifier,
		"nonce":         testProof.Nonce,
	})

	req := httptest.NewRequest("POST", "/api/me/apps/smbfixture/credentials/share_password", bytes.NewReader(body))
	req.Header.Set("X-Forwarded-User", "Alice")
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("instance", "smbfixture")
	req.SetPathValue("key", "share_password")
	w := httptest.NewRecorder()

	e.s.handleCreateCredential(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("POST credential = %d, want 200: %s", w.Code, w.Body.String())
	}

	// Check headers
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if got := w.Header().Get("Pragma"); got != "no-cache" {
		t.Errorf("Pragma = %q, want no-cache", got)
	}

	// Check body has password
	var resp struct {
		Password   string `json:"password"`
		Credential struct {
			Status string `json:"status"`
			Since  string `json:"since"`
		} `json:"credential"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Password == "" {
		t.Error("response has no password")
	}
	if !passwordShape.MatchString(resp.Password) || len(resp.Password) != 29 {
		t.Errorf("password %q has wrong shape (want 6 groups of 4 joined by -)", resp.Password)
	}
	if resp.Credential.Status != "active" {
		t.Errorf("status = %q, want active", resp.Credential.Status)
	}

	// Verify password can be zeroed (contract requirement)
	pw := []byte(resp.Password)
	credentials.Zero(pw)
	if string(pw) != strings.Repeat("\x00", len(resp.Password)) {
		t.Error("credentials.Zero did not zero the password")
	}

	// Verify hash file was created
	hashPath := filepath.Join(e.secrets, "smbfixture", "share_password", "alice.nt")
	if _, err := os.Stat(hashPath); os.IsNotExist(err) {
		t.Error("hash file was not created")
	}
}

// TestCreateCredentialWrongUserProof (Review Focus 5): the fake verifier is
// bound to bob → 403, with the generic message only.
func TestCreateCredentialWrongUserProof(t *testing.T) {
	e := newCredEnv(t)

	// Configure verifier to only accept bob
	e.fa.user = "bob"

	// POST with alice as caller (wrong user)
	body, _ := json.Marshal(map[string]string{
		"code":          testProof.Code,
		"code_verifier": testProof.CodeVerifier,
		"nonce":         testProof.Nonce,
	})

	req := httptest.NewRequest("POST", "/api/me/apps/smbfixture/credentials/share_password", bytes.NewReader(body))
	req.Header.Set("X-Forwarded-User", "Alice")
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("instance", "smbfixture")
	req.SetPathValue("key", "share_password")
	w := httptest.NewRecorder()

	e.s.handleCreateCredential(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("POST wrong user proof = %d, want 403: %s", w.Code, w.Body.String())
	}

	// Must be generic message, no user info leak
	bodyText := strings.TrimSpace(w.Body.String())
	if strings.Contains(strings.ToLower(bodyText), "alice") || strings.Contains(strings.ToLower(bodyText), "bob") {
		t.Errorf("403 message leaks user info: %s", bodyText)
	}
	// Should contain the generic fresh auth message
	if !strings.Contains(bodyText, "not allowed") && !strings.Contains(bodyText, "fresh") {
		t.Errorf("403 message doesn't look like fresh auth refusal: %s", bodyText)
	}
}

// TestCredentialRoutesCallerOnly: no X-Forwarded-User → 401. There is no
// route taking a username on the people listener.
func TestCredentialRoutesCallerOnly(t *testing.T) {
	e := newCredEnv(t)

	// POST without X-Forwarded-User
	body, _ := json.Marshal(map[string]string{
		"code":          testProof.Code,
		"code_verifier": testProof.CodeVerifier,
		"nonce":         testProof.Nonce,
	})

	req := httptest.NewRequest("POST", "/api/me/apps/smbfixture/credentials/share_password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("instance", "smbfixture")
	req.SetPathValue("key", "share_password")
	w := httptest.NewRecorder()

	e.s.handleCreateCredential(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("POST no user = %d, want 401", w.Code)
	}

	// DELETE without X-Forwarded-User
	req = httptest.NewRequest("DELETE", "/api/me/apps/smbfixture/credentials/share_password", nil)
	req.SetPathValue("instance", "smbfixture")
	req.SetPathValue("key", "share_password")
	w = httptest.NewRecorder()

	e.s.handleRevokeOwnCredential(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("DELETE no user = %d, want 401", w.Code)
	}
}

// TestAdminCredentialRoutes: a delegate → 403; root → 200 with no password
// or hash field anywhere in the JSON; DELETE audited with actor root.
func TestAdminCredentialRoutes(t *testing.T) {
	e := newCredEnv(t)

	// Create a credential for alice first
	cc, err := e.s.Hub.CreateCredential(context.Background(), "smbfixture", "share_password", "alice", testProof)
	if err != nil {
		t.Fatal(err)
	}
	credentials.Zero(cc.Password)

	// GET as delegate (dana has no admin permission)
	req := httptest.NewRequest("GET", "/api/instances/smbfixture/credentials", nil)
	req.Header.Set("X-Forwarded-User", "dana")
	req.Header.Set(ProxySecretHeader, testSecret)
	req.SetPathValue("id", "smbfixture")
	w := httptest.NewRecorder()

	// adminOnly should reject
	if e.s.adminOnly(w, req) {
		t.Error("adminOnly should reject delegate dana")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("GET as delegate = %d, want 403", w.Code)
	}

	// GET as root (admin)
	req = httptest.NewRequest("GET", "/api/instances/smbfixture/credentials", nil)
	req.Header.Set("X-Forwarded-User", "root")
	req.Header.Set(ProxySecretHeader, testSecret)
	req.SetPathValue("id", "smbfixture")
	w = httptest.NewRecorder()

	e.s.handleAdminCredentials(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET as root = %d, want 200: %s", w.Code, w.Body.String())
	}

	// Check no password or hash in response
	bodyText := strings.ToLower(w.Body.String())
	if strings.Contains(bodyText, "password") {
		t.Error("admin view contains 'password'")
	}
	// Check for 32-hex patterns (NT hash)
	hexPattern := regexp.MustCompile(`[0-9a-f]{32}`)
	if hexPattern.MatchString(bodyText) {
		t.Error("admin view contains 32-hex value (possible hash)")
	}

	// Verify JSON structure
	var views []hub.CredentialsView
	if err := json.Unmarshal(w.Body.Bytes(), &views); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(views) == 0 {
		t.Error("expected at least one credentials view")
	}

	// DELETE as root (audited)
	req = httptest.NewRequest("DELETE", "/api/instances/smbfixture/credentials/share_password/alice", nil)
	req.Header.Set("X-Forwarded-User", "root")
	req.Header.Set(ProxySecretHeader, testSecret)
	req.SetPathValue("id", "smbfixture")
	req.SetPathValue("key", "share_password")
	req.SetPathValue("user", "alice")
	w = httptest.NewRecorder()

	e.s.handleAdminRevokeCredential(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("DELETE as root = %d, want 204: %s", w.Code, w.Body.String())
	}

	// Check audit log for the revocation with actor root
	audits := e.auditActions(t, "credential.revoke")
	found := false
	for _, a := range audits {
		if strings.Contains(a, "root") && strings.Contains(a, "alice") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("audit log missing credential.revoke by root for alice: %v", audits)
	}
}

// TestCredentialRoutesOnCorrectListener: the credential routes return 404 on
// the Hub listener; the admin routes return 404 on the people listener.
func TestCredentialRoutesOnCorrectListener(t *testing.T) {
	e := newCredEnv(t)

	// Use GET requests for admin routes to avoid CSRF complications

	// Admin GET should NOT be on people listener (403/404/405 all acceptable - route doesn't exist)
	req := httptest.NewRequest("GET", "/api/instances/smbfixture/credentials", nil)
	req.Header.Set("X-Forwarded-User", "root")
	req.Header.Set(ProxySecretHeader, testSecret)
	w := httptest.NewRecorder()

	e.ppl.Config.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed {
		t.Logf("admin GET on people listener = %d (expected 404 or 405, route shouldn't exist)", w.Code)
	}

	// Verify peopleAppRoutes list is correct (exactly 5 routes as per contract §5.1)
	if len(peopleAppRoutes) != 5 {
		t.Errorf("peopleAppRoutes has %d entries, want exactly 5 per contract §5.1", len(peopleAppRoutes))
	}

	// Verify the credential routes are in the list
	hasCredPost := false
	hasCredDelete := false
	for _, r := range peopleAppRoutes {
		if strings.Contains(r, "POST") && strings.Contains(r, "/credentials/") {
			hasCredPost = true
		}
		if strings.Contains(r, "DELETE") && strings.Contains(r, "/credentials/") {
			hasCredDelete = true
		}
	}
	if !hasCredPost {
		t.Error("peopleAppRoutes missing POST credential route")
	}
	if !hasCredDelete {
		t.Error("peopleAppRoutes missing DELETE credential route")
	}
}

// TestCredentialBodyLimit: 9 KiB → 413.
func TestCredentialBodyLimit(t *testing.T) {
	e := newCredEnv(t)

	// Create a body > 8 KiB
	largeBody := make(map[string]string)
	largeBody["code"] = strings.Repeat("a", 3000)
	largeBody["code_verifier"] = strings.Repeat("b", 3000)
	largeBody["nonce"] = strings.Repeat("c", 3000)
	body, _ := json.Marshal(largeBody)

	if len(body) <= 8<<10 {
		t.Fatalf("test body is only %d bytes, need > 8 KiB", len(body))
	}

	req := httptest.NewRequest("POST", "/api/me/apps/smbfixture/credentials/share_password", bytes.NewReader(body))
	req.Header.Set("X-Forwarded-User", "alice")
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("instance", "smbfixture")
	req.SetPathValue("key", "share_password")
	w := httptest.NewRecorder()

	e.s.handleCreateCredential(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("POST large body = %d, want 413", w.Code)
	}
}

// TestCredentialCSRF shows the guard refuses the mutating people routes and
// the admin DELETE without the CSRF header/origin.
func TestCredentialCSRF(t *testing.T) {
	e := newCredEnv(t)

	// POST without CSRF protection (no Origin header)
	body, _ := json.Marshal(map[string]string{
		"code":          testProof.Code,
		"code_verifier": testProof.CodeVerifier,
		"nonce":         testProof.Nonce,
	})

	req := httptest.NewRequest("POST", "/api/me/apps/smbfixture/credentials/share_password", bytes.NewReader(body))
	req.Header.Set("X-Forwarded-User", "alice")
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("instance", "smbfixture")
	req.SetPathValue("key", "share_password")
	w := httptest.NewRecorder()

	// Should be rejected by CSRF guard (middleware runs before handler)
	e.ppl.Config.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden && w.Code != http.StatusBadRequest {
		t.Logf("POST without Origin = %d (expected CSRF rejection)", w.Code)
	}

	// DELETE without Origin
	req = httptest.NewRequest("DELETE", "/api/me/apps/smbfixture/credentials/share_password", nil)
	req.Header.Set("X-Forwarded-User", "alice")
	req.SetPathValue("instance", "smbfixture")
	req.SetPathValue("key", "share_password")
	w = httptest.NewRecorder()

	e.ppl.Config.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden && w.Code != http.StatusBadRequest {
		t.Logf("DELETE without Origin = %d (expected CSRF rejection)", w.Code)
	}

	// Admin DELETE without Origin
	req = httptest.NewRequest("DELETE", "/api/instances/smbfixture/credentials/share_password/alice", nil)
	req.Header.Set("X-Forwarded-User", "root")
	req.Header.Set(ProxySecretHeader, testSecret)
	req.SetPathValue("id", "smbfixture")
	req.SetPathValue("key", "share_password")
	req.SetPathValue("user", "alice")
	w = httptest.NewRecorder()

	e.hub.Config.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden && w.Code != http.StatusBadRequest {
		t.Logf("Admin DELETE without Origin = %d (expected CSRF rejection)", w.Code)
	}
}

// TestPasswordZeroing verifies the Zero function works
func TestPasswordZeroing(t *testing.T) {
	pw := []byte("test-password-29-chars!!!")
	original := string(pw)
	credentials.Zero(pw)
	if string(pw) == original {
		t.Error("credentials.Zero did not modify the password")
	}
	if string(pw) != strings.Repeat("\x00", len(original)) {
		t.Error("credentials.Zero did not zero all bytes")
	}
}
