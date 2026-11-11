package hub

// Settings → Sign-in limits (contract §8.1 "Limits", plan D27) and the
// Keycloak events config the Hub owns (§8 "Keycloak's events config",
// D28): browser_cert_days (1 to the ceiling, HUB_CLIENT_CERT_TTL in whole
// days; a stored value above it applies as the ceiling, with a warning),
// browser_cert_max_active (1–20) and history_days (30–3650), which is
// also Keycloak's eventsExpiration.

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/state"
)

// eventsEnsureTimeout bounds one events-config re-assertion.
const eventsEnsureTimeout = 30 * time.Second

// LimitsView is the limits as stored, the ceiling of browser_cert_days,
// what applies (Effective: browser_cert_days capped at the ceiling) and,
// only while a stored value is above the ceiling, a warning.
type LimitsView struct {
	Limits      state.SignInLimits `json:"limits"`
	CeilingDays int                `json:"ceiling_days"`
	Effective   state.SignInLimits `json:"effective"`
	Warning     string             `json:"warning,omitempty"`
}

// ceilingDays is HUB_CLIENT_CERT_TTL in whole days.
func (h *Hub) ceilingDays() int {
	return int(h.cfg.ClientCertTTL / (24 * time.Hour))
}

// limitsViewLocked is the limits view. Caller holds mu (either lock).
func (h *Hub) limitsViewLocked() LimitsView {
	l := h.st.SignIn.Limits
	v := LimitsView{Limits: l, CeilingDays: h.ceilingDays(), Effective: l}
	if l.BrowserCertDays > v.CeilingDays {
		v.Effective.BrowserCertDays = v.CeilingDays
		v.Warning = fmt.Sprintf("The browser certificate lifetime is set to %d days, more than this server allows (%d days, the core's CLIENT_CERT_TTL): %d days apply. Save a lifetime of at most %d days.",
			l.BrowserCertDays, v.CeilingDays, v.CeilingDays, v.CeilingDays)
	}
	return v
}

// SignInLimits is the limits view.
func (h *Hub) SignInLimits() LimitsView {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.limitsViewLocked()
}

// SetEventsConfig sets how Keycloak's events config is re-asserted
// (main: keycloak.Client.EnsureEventsConfig); the directory sync loop and
// every limits change call it with history_days.
func (h *Hub) SetEventsConfig(ensure func(ctx context.Context, days int) error) {
	h.policyWriteMu.Lock()
	defer h.policyWriteMu.Unlock()
	h.eventsEnsure = ensure
}

// ensureEvents re-asserts the events config with the stored
// history_days (nil when none is wired).
func (h *Hub) ensureEvents(ctx context.Context) error {
	h.policyWriteMu.Lock()
	ensure := h.eventsEnsure
	h.policyWriteMu.Unlock()
	if ensure == nil {
		return nil
	}
	h.mu.RLock()
	days := h.st.SignIn.Limits.HistoryDays
	h.mu.RUnlock()
	return ensure(ctx, days)
}

// checkLimits is the route's bounds: state's plus the ceiling.
func checkLimits(in state.SignInLimits, ceiling int) error {
	if in.BrowserCertDays < 1 || in.BrowserCertDays > ceiling {
		if ceiling < 1 {
			return statusErr(http.StatusBadRequest, "browser_cert_days: this server allows no browser certificate lifetime (HUB_CLIENT_CERT_TTL is under a day)")
		}
		return statusErr(http.StatusBadRequest, "browser_cert_days must be 1 to %d (the server's longest browser certificate lifetime), got %d", ceiling, in.BrowserCertDays)
	}
	if in.BrowserCertMaxActive < 1 || in.BrowserCertMaxActive > state.MaxBrowserCertMaxActive {
		return statusErr(http.StatusBadRequest, "browser_cert_max_active must be 1 to %d, got %d", state.MaxBrowserCertMaxActive, in.BrowserCertMaxActive)
	}
	if in.HistoryDays < state.MinHistoryDays || in.HistoryDays > state.MaxHistoryDays {
		return statusErr(http.StatusBadRequest, "history_days must be %d to %d, got %d", state.MinHistoryDays, state.MaxHistoryDays, in.HistoryDays)
	}
	return nil
}

// CheckSignInLimits is SetSignInLimits' bounds check (the MCP twin's
// precheck): nil, or the route's 400.
func (h *Hub) CheckSignInLimits(in state.SignInLimits) error {
	return checkLimits(in, h.ceilingDays())
}

// limitsDetail is the audit detail: "<field> old -> new" per changed
// field ("" = nothing changed).
func limitsDetail(old, next state.SignInLimits) string {
	var parts []string
	add := func(name string, a, b int) {
		if a != b {
			parts = append(parts, fmt.Sprintf("%s %d -> %d", name, a, b))
		}
	}
	add("browser_cert_days", old.BrowserCertDays, next.BrowserCertDays)
	add("browser_cert_max_active", old.BrowserCertMaxActive, next.BrowserCertMaxActive)
	add("history_days", old.HistoryDays, next.HistoryDays)
	return strings.Join(parts, "; ")
}

// SetSignInLimits saves the three limits (all required; out of bounds
// 400, browser_cert_days above the ceiling included), audited
// signin.limits with an old -> new detail per changed field, then
// re-asserts Keycloak's events config (a failure is logged: the sync
// loop retries). Nothing changed: no save, no audit.
func (h *Hub) SetSignInLimits(ctx context.Context, in state.SignInLimits, actor directory.Actor) (v *LimitsView, err error) {
	attempt := fmt.Sprintf("browser_cert_days %d; browser_cert_max_active %d; history_days %d", in.BrowserCertDays, in.BrowserCertMaxActive, in.HistoryDays)
	detail := ""
	defer func() {
		if err != nil {
			h.auditSignIn(actor, "signin.limits", "limits", attempt, err)
		} else if detail != "" {
			h.auditSignIn(actor, "signin.limits", "limits", detail, nil)
		}
	}()
	if actor.User == "" {
		return nil, statusErr(http.StatusUnauthorized, "changing the sign-in settings needs a signed-in admin")
	}
	if err := checkLimits(in, h.ceilingDays()); err != nil {
		return nil, err
	}
	h.signInMu.Lock()
	defer h.signInMu.Unlock()
	h.mu.Lock()
	prev := h.st.SignIn.Limits
	d := limitsDetail(prev, in)
	if d == "" {
		view := h.limitsViewLocked()
		h.mu.Unlock()
		return &view, nil
	}
	h.st.SignIn.Limits = in
	if err := h.saveStateLocked(); err != nil {
		h.st.SignIn.Limits = prev
		h.mu.Unlock()
		return nil, err
	}
	view := h.limitsViewLocked()
	h.mu.Unlock()
	detail = d
	ectx, cancel := context.WithTimeout(context.WithoutCancel(ctx), eventsEnsureTimeout)
	defer cancel()
	if err := h.ensureEvents(ectx); err != nil {
		log.Printf("keycloak: events config not re-asserted after the limits change (the sync loop retries): %v", err)
	}
	return &view, nil
}
