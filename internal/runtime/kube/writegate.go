package kube

import (
	"net/http"
	"strings"

	"github.com/portcullis/hub/internal/fsutil"
)

// GateWrites wraps a client transport so that every request that changes
// the cluster asks the write gate first (contract §20.5: a Hub that isn't
// the active writer applies, creates, deletes, patches and execs
// nothing). Reads pass, and so do the requests that only ask: access and
// token reviews (the cluster guard's checks) and dry runs. Wrap the
// backend's clients with it, never the Lease's own.
func GateWrites(rt http.RoundTripper) http.RoundTripper {
	return gatedTransport{rt}
}

type gatedTransport struct{ next http.RoundTripper }

func (g gatedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if changesCluster(r) {
		if err := fsutil.CheckWrite(); err != nil {
			if r.Body != nil {
				r.Body.Close()
			}
			return nil, err
		}
	}
	return g.next.RoundTrip(r)
}

// changesCluster: r may change something (a write verb, or an upgraded
// stream: exec, attach, port-forward).
func changesCluster(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return r.Header.Get("Upgrade") != "" || isStream(r.URL.Path)
	}
	if r.Method == http.MethodPost && (strings.HasPrefix(r.URL.Path, "/apis/authorization.k8s.io/") || strings.HasPrefix(r.URL.Path, "/apis/authentication.k8s.io/")) {
		return false
	}
	if q := r.URL.Query()["dryRun"]; len(q) == 1 && q[0] == "All" {
		return false
	}
	return true
}

func isStream(path string) bool {
	return strings.HasSuffix(path, "/exec") || strings.HasSuffix(path, "/attach") || strings.HasSuffix(path, "/portforward")
}
