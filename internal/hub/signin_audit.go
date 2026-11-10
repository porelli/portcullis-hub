package hub

import (
	"errors"
	"log"

	"github.com/portcullis/hub/internal/directory"
)

// auditSignIn records a Settings → Sign-in change (D12: signin.method,
// signin.template, signin.template_enabled, signin.template_delete,
// signin.default, signin.core, signin.add_stronger), after mu. A 4xx is
// `refused`, anything else failing `error`. Sign-in errors carry no
// secrets (passwords never reach this path, D13).
func (h *Hub) auditSignIn(actor directory.Actor, action, target, detail string, err error) {
	h.mu.RLock()
	a := h.audit
	h.mu.RUnlock()
	if a == nil {
		return
	}
	e := directory.AuditEntry{Actor: actor.User, Via: actor.Via, Client: actor.Client, Action: action, Target: clip(target, 64), Detail: actor.AuditDetail(clipRunes(detail, 600)), Result: "ok"}
	if err != nil {
		e.Result = "error"
		var se *StatusError
		if errors.As(err, &se) && se.Status < 500 {
			e.Result = "refused"
		}
		e.Error = clipRunes(err.Error(), 600)
	}
	if aerr := a.Append(e); aerr != nil {
		log.Printf("audit: %v", aerr)
	}
}
