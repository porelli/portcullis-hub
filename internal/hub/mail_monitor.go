package hub

import (
	"encoding/json"
	"log"
	"os"
	"strconv"
)

// Metrics discovery (contract §19.8, P7): mail_slot/mail-targets.json
// (file_sd), written in place on every wire, unwire and Hub start: []
// when nothing is wired or the provider isn't in normal mode (so the
// generic up == 0 alert never fires for an empty slot), else the
// provider's metrics target and, with server_metrics, the server's.

const mailTargetsFile = "mail-targets.json"

type mailTarget struct {
	Targets []string          `json:"targets"`
	Labels  map[string]string `json:"labels"`
}

// mailTargetsLocked is the file_sd content. Caller must hold mu (read).
func (h *Hub) mailTargetsLocked() []mailTarget {
	out := []mailTarget{}
	p := h.st.Mail.Provider
	if p == nil || h.mailModeLocked(p.Instance) != mailNormal {
		return out
	}
	_, m := h.mailWiredLocked()
	if m == nil {
		return out
	}
	out = append(out, mailTarget{Targets: []string{mailMetricsAlias + ":" + strconv.Itoa(m.Metrics.Port)}, Labels: map[string]string{"service": "provider"}})
	if sm := m.ServerMetrics; sm != nil {
		out = append(out, mailTarget{Targets: []string{mailServerMetricsAlias + ":" + strconv.Itoa(sm.Port)},
			Labels: map[string]string{"service": "server", "__metrics_path__": sm.Path}})
	}
	return out
}

// writeMailTargets writes mail-targets.json (a failure is logged:
// Prometheus keeps the last file).
func (h *Hub) writeMailTargets() {
	if h.cfg.MailSlotDir == "" {
		return
	}
	h.mu.RLock()
	b, err := json.Marshal(h.mailTargetsLocked())
	h.mu.RUnlock()
	if err != nil {
		return
	}
	r, err := os.OpenRoot(h.cfg.MailSlotDir)
	if err != nil {
		log.Printf("mail: the mail_slot volume: %v", err)
		return
	}
	defer r.Close()
	if err := writeInPlace(r, mailTargetsFile, append(b, '\n'), -1); err != nil {
		log.Printf("mail: writing %s: %v", mailTargetsFile, err)
	}
}
