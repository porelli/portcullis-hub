package hub

// Signed host requests (plan C6): an SSHSIG by the pinned host key over
// the canonical message, time within ±60 s, a nonce never reused for 5
// minutes. Unknown, removed or unpinned hosts get 403 removed.

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"time"

	"github.com/hiddeco/sshsig"

	"github.com/portcullis/hub/internal/cliapi"
)

const (
	hostClockSkew = 60 * time.Second
	hostNonceKeep = 5 * time.Minute
)

// VerifyHostRequest checks r's signature over body and answers the host
// id. Every failure is a refusal that names nothing the request carried.
func (h *Hub) VerifyHostRequest(r *http.Request, body []byte) (string, error) {
	if !h.SSHEnabled() {
		return "", refusal(http.StatusServiceUnavailable, TextHostsOff, "ssh off")
	}
	id := r.Header.Get(cliapi.HeaderHostID)
	tm := r.Header.Get(cliapi.HeaderHostTime)
	nonce := r.Header.Get(cliapi.HeaderHostNonce)
	sigH := r.Header.Get(cliapi.HeaderHostSignature)
	bad := refusal(http.StatusForbidden, "the request signature is wrong", "bad signature")
	if !cliapi.ValidHostID(id) {
		return "", refusal(http.StatusForbidden, TextRemoved, "bad host id")
	}
	h.mu.RLock()
	hst, ok := h.st.SSH.Hosts[id]
	h.mu.RUnlock()
	if !ok || !hst.Managed || hst.Removed || hst.HostKey == "" {
		return "", refusal(http.StatusForbidden, TextRemoved, "unknown, removed or unpinned host")
	}
	now := h.sshrt.clock()
	t, err := time.Parse(time.RFC3339, tm)
	if err != nil || t.Before(now.Add(-hostClockSkew)) || t.After(now.Add(hostClockSkew)) {
		return "", refusal(http.StatusForbidden, "the host's clock is off by more than 60 s", "time outside ±60 s")
	}
	if nb, err := base64.RawURLEncoding.Strict().DecodeString(nonce); err != nil || len(nb) != 16 {
		return "", bad
	}
	key, _, err := cliapi.ParseAuthorizedKey(hst.HostKey)
	if err != nil {
		return "", refusal(http.StatusForbidden, TextRemoved, "pinned key unreadable")
	}
	sig, err := sshsig.Unarmor(cliapi.DecodeSignatureHeader(sigH))
	if err != nil {
		return "", bad
	}
	msg := cliapi.HostRequestMessage(id, r.Method, r.URL.Path, r.URL.RawQuery, tm, nonce, body)
	if sshsig.Verify(bytes.NewReader(msg), sig, key, sshsig.HashSHA512, cliapi.NSHostRequest) != nil {
		return "", bad
	}
	h.sshhosts.mu.Lock()
	defer h.sshhosts.mu.Unlock()
	h.sshhosts.init()
	for k, first := range h.sshhosts.nonces {
		if now.Sub(first) > hostNonceKeep {
			delete(h.sshhosts.nonces, k)
		}
	}
	nk := id + "|" + nonce
	if _, seen := h.sshhosts.nonces[nk]; seen {
		return "", refusal(http.StatusForbidden, "the request was replayed", "nonce replayed")
	}
	h.sshhosts.nonces[nk] = now
	h.sshhosts.lastSync[id] = now
	return id, nil
}

// HostLastSync is the host's last signed request (memory, then state).
func (h *Hub) HostLastSync(id string) time.Time {
	h.sshhosts.mu.Lock()
	t, ok := h.sshhosts.lastSync[id]
	h.sshhosts.mu.Unlock()
	if ok {
		return t
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.st.SSH.Hosts[id].LastSync
}
