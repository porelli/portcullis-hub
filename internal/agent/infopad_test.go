package agent

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/agentapi"
	"github.com/portcullis/hub/internal/e2etest"
)

// TestOversizeInfoOnlyInE2E: AGENT_TEST_OVERSIZE_INFO pads /v1/info past
// 64 KiB (still valid JSON) in an e2etest build only; a default build
// answers the normal size whatever the config says.
func TestOversizeInfoOnlyInE2E(t *testing.T) {
	a := &Agent{cfg: Config{DataDir: t.TempDir(), Runtime: "docker", Now: time.Now, OversizeInfo: true,
		Info: func(context.Context) (agentapi.Info, error) { return agentapi.Info{}, nil }}}
	rec := httptest.NewRecorder()
	a.handleInfo(rec, httptest.NewRequest("GET", "/v1/info", nil))
	var v agentapi.Info
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &v) != nil {
		t.Fatalf("%d %.200s", rec.Code, rec.Body.String())
	}
	big := rec.Body.Len() > 64<<10
	if big != e2etest.Enabled {
		t.Errorf("e2etest %v: %d bytes", e2etest.Enabled, rec.Body.Len())
	}
}
