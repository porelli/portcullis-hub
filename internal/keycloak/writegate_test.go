package keycloak

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/portcullis/hub/internal/fsutil"
)

// TestNoKeycloakWriteWhileStandingBy: with the write gate closed, the
// admin client still signs in and reads, but no write reaches Keycloak.
func TestNoKeycloakWriteWhileStandingBy(t *testing.T) {
	var mu sync.Mutex
	var writes []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/protocol/openid-connect/token"):
			w.Write([]byte(`{"access_token":"t","expires_in":300,"token_type":"bearer"}`))
			return
		case r.Method != http.MethodGet:
			mu.Lock()
			writes = append(writes, r.Method+" "+r.URL.Path)
			mu.Unlock()
		}
		if strings.Contains(r.URL.Path, "/users") {
			w.Write([]byte(`[{"id":"0b6a1c2e-3d4f-4a5b-8c6d-7e8f9a0b1c2d","username":"alice","requiredActions":[]}]`))
			return
		}
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	standBy := errors.New("this Hub is standing by: another Hub is the active writer")
	fsutil.SetWriteGate(func() error { return standBy })
	t.Cleanup(func() { fsutil.SetWriteGate(nil) })
	c := New(srv.URL, "admin", "pw")
	if err := c.RequireImpersonationNotice(context.Background(), "alice"); !errors.Is(err, standBy) {
		t.Errorf("RequireImpersonationNotice = %v, want the gate's error", err)
	}
	if _, err := c.RequiredActions(context.Background(), "alice"); err != nil {
		t.Errorf("a read while standing by = %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(writes) != 0 {
		t.Errorf("writes reached Keycloak while standing by: %v", writes)
	}
}
