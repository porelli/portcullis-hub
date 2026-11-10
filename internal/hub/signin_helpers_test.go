package hub

import (
	"github.com/portcullis/hub/internal/signin"
	"github.com/portcullis/hub/internal/state"
)

// certOnlyTemplate is the built-in certificate-only template (all of
// yubikey_cert, security_key; starts disabled).
const certOnlyTemplate = "yubikey-and-certificate"

// setPickLocked sets instance id's sign-in template pick in state ("" =
// the default), enabling the picked template; no save, no checks (test
// helper). Caller holds h.mu.
func setPickLocked(h *Hub, id, pick string) {
	if tm, ok := h.st.SignIn.Templates[pick]; ok && !tm.Enabled {
		tm.Enabled = true
		h.st.SignIn.Templates[pick] = tm
	}
	e, had := h.st.Instances[id]
	if !had {
		tid := id
		if t := h.findLocked(id); t != nil {
			tid = t.TemplateID
		}
		e = state.Instance{ID: id, Template: tid}
	}
	e.SignInTemplate = pick
	if entryHoldsNothing(e) {
		delete(h.st.Instances, id)
	} else {
		h.st.Instances[id] = e
	}
}

// setCertOnlyLocked puts instance id on the certificate-only built-in.
// Caller holds h.mu.
func setCertOnlyLocked(h *Hub, id string) { setPickLocked(h, id, certOnlyTemplate) }

// addTemplateLocked stores an enabled template id with rule (test
// helper). Caller holds h.mu.
func addTemplateLocked(h *Hub, id string, rule signin.Node) {
	h.st.SignIn.Templates[id] = state.SignInTemplate{Name: id, Rule: rule, Enabled: true}
}
