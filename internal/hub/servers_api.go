package hub

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/servers"
	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// The Servers page's reads and settings (contract §17.3, Task 12). The
// routes are admin only; adding, revoking and removing a server, undoing
// a move, removing its leftover and lifting a quarantine also need a
// fresh sign-in on the Hub listener (CheckAdminFresh).

// ServerDetail is GET /api/servers/{id}: the list's view plus the
// server's Local networks, folder roots and backup schedule. Never a join
// code, a key, a secret or a serial.
type ServerDetail struct {
	ServerView
	LocalNetworks        []string             `json:"local_networks"`
	LocalNetworksDefault bool                 `json:"local_networks_default"`
	BackupSchedule       state.BackupSchedule `json:"backup_schedule"`
}

// ServerDetailOf is one server's detail ("primary" = the primary); 404
// for an unknown id.
func (h *Hub) ServerDetailOf(ctx context.Context, id string) (*ServerDetail, error) {
	for _, v := range h.Servers(ctx) {
		if v.ID != id {
			continue
		}
		d := &ServerDetail{ServerView: v}
		if id == servers.PrimaryID {
			d.LocalNetworks, d.LocalNetworksDefault = h.LocalNetworksView()
			d.BindRoots = slices.Clone(h.bindRoots)
			h.mu.RLock()
			d.BackupSchedule = h.st.PrimaryBackups
			h.mu.RUnlock()
		} else {
			h.mu.RLock()
			s := h.st.Servers[id]
			h.mu.RUnlock()
			if s.LocalNetworks == nil {
				d.LocalNetworks, d.LocalNetworksDefault = slices.Clone(DefaultLocalNetworks), true
			} else {
				d.LocalNetworks = slices.Clone(*s.LocalNetworks)
			}
			d.BackupSchedule = s.BackupSchedule
		}
		if d.BackupSchedule.Mode == "" {
			d.BackupSchedule.Mode = "off"
		}
		return d, nil
	}
	return nil, statusErr(http.StatusNotFound, "no server %s", id)
}

// ServerSettings is PUT /api/servers/{id}/settings: each field optional
// (nil = unchanged). LocalNetworksDefault puts the Local networks back
// to the defaults (with LocalNetworks unset).
type ServerSettings struct {
	Name                 *string
	LocalNetworks        *[]string
	LocalNetworksDefault bool
	BackupSchedule       *state.BackupSchedule
}

// validBackupSchedule: mode off, daily or weekly; hour 0–23; weekday
// 0–6, and only for weekly.
func validBackupSchedule(s state.BackupSchedule) error {
	switch s.Mode {
	case "off", "daily", "weekly":
	default:
		return statusErr(http.StatusBadRequest, "backup_schedule.mode is off, daily or weekly")
	}
	if s.Hour < 0 || s.Hour > 23 {
		return statusErr(http.StatusBadRequest, "backup_schedule.hour is 0–23")
	}
	if s.Weekday < 0 || s.Weekday > 6 {
		return statusErr(http.StatusBadRequest, "backup_schedule.weekday is 0–6 (0 = Sunday)")
	}
	if s.Mode != "weekly" && s.Weekday != 0 {
		return statusErr(http.StatusBadRequest, "backup_schedule.weekday is for a weekly schedule only")
	}
	return nil
}

// SetServerSettings changes a server's name, Local networks and backup
// schedule ("primary": the schedule only). Audited server.settings,
// naming what changed (never a secret). A changed Local networks list
// restarts the server's enabled instances whose compose reads it.
func (h *Hub) SetServerSettings(ctx context.Context, actor directory.Actor, id string, in ServerSettings) (err error) {
	var changed []string
	defer func() { h.auditOp(actor, "server.settings", id, strings.Join(changed, ", "), err) }()
	if actor.User == "" {
		return statusErr(http.StatusUnauthorized, "no acting user")
	}
	if in.BackupSchedule != nil {
		if err := validBackupSchedule(*in.BackupSchedule); err != nil {
			return err
		}
	}
	if id == servers.PrimaryID {
		if in.Name != nil || in.LocalNetworks != nil || in.LocalNetworksDefault {
			return statusErr(http.StatusBadRequest, "the primary's settings here are its backup schedule only (Local networks: Settings → Local networks)")
		}
		if in.BackupSchedule == nil {
			return nil
		}
		h.mu.Lock()
		prev := h.st.PrimaryBackups
		h.st.PrimaryBackups = *in.BackupSchedule
		if err := h.saveStateLocked(); err != nil {
			h.st.PrimaryBackups = prev
			h.mu.Unlock()
			return err
		}
		h.mu.Unlock()
		changed = append(changed, "backup_schedule="+scheduleText(*in.BackupSchedule))
		return nil
	}
	if err := servers.ValidID(id); err != nil {
		return statusErr(http.StatusNotFound, "no server %s", id)
	}
	var name string
	if in.Name != nil {
		if name, err = validServerName(id, *in.Name); err != nil {
			return err
		}
	}
	var nets *[]string
	if in.LocalNetworks != nil && in.LocalNetworksDefault {
		return statusErr(http.StatusBadRequest, "local_networks: a list or the defaults, not both")
	}
	if in.LocalNetworks != nil {
		ps, err := state.ParseLocalNetworks(*in.LocalNetworks)
		if err != nil {
			return statusErr(http.StatusBadRequest, "local networks: %v", err)
		}
		list := make([]string, 0, len(ps))
		for _, p := range ps {
			list = append(list, p.String())
		}
		nets = &list
	}
	h.mu.Lock()
	s, ok := h.st.Servers[id]
	if !ok {
		h.mu.Unlock()
		return statusErr(http.StatusNotFound, "no server %s", id)
	}
	if s.State == ServerRevoked {
		h.mu.Unlock()
		return statusErr(http.StatusConflict, "server %s is revoked: remove it", id)
	}
	prev := s
	prevEnv := map[string]string{}
	for iid, inst := range h.st.Instances {
		if inst.Server == id {
			prevEnv[iid] = h.localNetworksEnvForLocked(iid)
		}
	}
	if in.Name != nil && name != s.Name {
		s.Name = name
		changed = append(changed, "name")
	}
	if nets != nil || in.LocalNetworksDefault {
		s.LocalNetworks = nets
		changed = append(changed, fmt.Sprintf("local_networks=%d", localCount(nets)))
	}
	if in.BackupSchedule != nil {
		s.BackupSchedule = *in.BackupSchedule
		changed = append(changed, "backup_schedule="+scheduleText(*in.BackupSchedule))
	}
	h.st.Servers[id] = s
	if err := h.saveStateLocked(); err != nil {
		h.st.Servers[id] = prev
		h.mu.Unlock()
		changed = nil
		return err
	}
	var restart []templates.Template
	for iid, was := range prevEnv {
		if h.localNetworksEnvForLocked(iid) == was || !h.st.IsEnabled(iid) {
			continue
		}
		if t := h.findLocked(iid); t != nil && t.UsesLocalNetworks {
			restart = append(restart, *t)
		}
	}
	h.mu.Unlock()
	for _, t := range restart {
		h.setOwed(t.ID, settings.EffectRestart)
		h.goBackground(func() { h.Restart(t) })
	}
	return nil
}

func localCount(nets *[]string) int {
	if nets == nil {
		return len(DefaultLocalNetworks)
	}
	return len(*nets)
}

func scheduleText(s state.BackupSchedule) string {
	switch s.Mode {
	case "daily":
		return fmt.Sprintf("daily %02d:00", s.Hour)
	case "weekly":
		return fmt.Sprintf("weekly %d %02d:00", s.Weekday, s.Hour)
	}
	return "off"
}

// CheckAdminFresh checks an admin's fresh sign-in on the Hub listener
// (contract §17.3 †: as the VPN device routes), governed by the hub
// page's template. A refusal is audited as action "refused: <reason>"
// (never the proof) and answers 403 "a fresh sign-in is required" (503
// while the Hub can't check proofs).
func (h *Hub) CheckAdminFresh(ctx context.Context, actor directory.Actor, action, target string, p freshauth.Proof) error {
	if actor.User == "" {
		return statusErr(http.StatusUnauthorized, "no acting user")
	}
	if p.Code == "" || p.CodeVerifier == "" || p.Nonce == "" {
		// No proof: refused before any exchange (fail closed).
		h.auditOp(actor, action, target, "fresh sign-in refused: no proof", errFreshAuth)
		return errFreshAuth
	}
	_, reason, err := h.checkFreshAuthOn(ctx, ListenerHub, govCore("hub"), p, actor.User)
	if err != nil {
		h.auditOp(actor, action, target, "fresh sign-in refused: "+reason, err)
		return err
	}
	return nil
}

// AdminFreshAuthInfo is the Hub listener's fresh sign-in popup
// parameters (nil without a verifier): the Servers page starts its †
// actions with them.
func (h *Hub) AdminFreshAuthInfo() *freshauth.AuthorizeInfo { return h.FreshAuthInfoFor(ListenerHub) }

// StartMove is MoveInstance in the background (POST
// /api/instances/{id}/move: 202, op move). A refusal before the move is
// accepted is synchronous.
func (h *Hub) StartMove(id, to string, actor directory.Actor) (*AsyncOp, error) {
	return h.startAsync(id, OpMove, actor, movePlan(), func(ctx context.Context, ready func()) (map[string]string, []string, error) {
		return nil, nil, h.moveInstance(ctx, id, normServer(to), actor, ready)
	})
}

// StartUndoMove is UndoMove in the background (202, op move_undo).
func (h *Hub) StartUndoMove(id, confirm string, actor directory.Actor) (*AsyncOp, error) {
	return h.startAsync(id, OpMoveUndo, actor, undoPlan(), func(ctx context.Context, ready func()) (map[string]string, []string, error) {
		return nil, nil, h.undoMove(ctx, id, confirm, actor, ready)
	})
}

// StartForget is ForgetInstance in the background (DELETE
// /api/instances/{id}?forget=1: 202, op delete).
func (h *Hub) StartForget(id, confirm string, actor directory.Actor) (*AsyncOp, error) {
	h.mu.RLock()
	in, ok := h.st.Instances[id]
	h.mu.RUnlock()
	if !ok || in.State != state.InstanceOrphaned {
		err := statusErr(http.StatusConflict, "only an orphaned instance can be forgotten (its server revoked): delete %s instead", id)
		h.auditOp(actor, "instance.forget", id, "", err)
		return nil, err
	}
	return h.startAsync(id, OpDelete, actor, []Step{}, func(ctx context.Context, ready func()) (map[string]string, []string, error) {
		return deleteResult(h.deleteInstance(context.WithValue(ctx, forgetKey{}, true), id, confirm, actor, ready))
	})
}
