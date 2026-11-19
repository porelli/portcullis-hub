package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/portcullis/hub/internal/hub"
)

// TestHostErrBusyIs409: a busy instance is the host socket's 409 with
// the Hub's text, never the bare 500 "the Hub couldn't do it".
func TestHostErrBusyIs409(t *testing.T) {
	rec := httptest.NewRecorder()
	hostErr(rec, hub.ErrBusy{ID: "stalwart"})
	if rec.Code != http.StatusConflict || rec.Body.String() == "the Hub couldn't do it: see its log\n" {
		t.Fatalf("%d %q", rec.Code, rec.Body.String())
	}
}
