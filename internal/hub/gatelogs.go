package hub

import (
	"context"
	"errors"
	"time"

	"github.com/portcullis/hub/internal/gatelogs"
	"github.com/portcullis/hub/internal/signinhistory"
	"github.com/portcullis/hub/internal/vpn"
)

// GateLogSources are the per-replica sources of Kubernetes HA (contract
// §20.10, Config.GateLogs): Opened group-gate's opened log, Access
// mcp-gate's access log (its tail), WGStatus wg's status document. A nil
// one is that source missing (as an unset directory or file is).
type GateLogSources struct {
	Opened   gatelogs.Source
	Access   *gatelogs.Tail
	WGStatus gatelogs.StatusSource
}

// wgStatusTimeout bounds one read of wg's status over its port.
const wgStatusTimeout = 5 * time.Second

// openedLogOn: the opened log has a source (the directory, or group-gate's
// replicas).
func (h *Hub) openedLogOn() bool {
	return h.cfg.GroupGateDataDir != "" || h.cfg.GateLogs != nil && h.cfg.GateLogs.Opened != nil
}

// openedLog is group-gate's opened log: under HUB_GROUP_GATE_DATA_DIR, or
// read from its replicas (HUB_GATE_LOG_SOURCES=http).
func (h *Hub) openedLog() signinhistory.OpenedLog {
	l := signinhistory.OpenedLog{Dir: h.cfg.GroupGateDataDir, Now: h.historyNow}
	if h.cfg.GateLogs != nil && h.cfg.GateLogs.Opened != nil {
		l.Src = h.cfg.GateLogs.Opened
	}
	return l
}

// accessTail is the access log read from mcp-gate's replicas (nil: the
// file, or none).
func (h *Hub) accessTail() *gatelogs.Tail {
	if h.cfg.GateLogs == nil {
		return nil
	}
	return h.cfg.GateLogs.Access
}

// vpnStatusOn: wg's status has a source (the file, or wg's port).
func (h *Hub) vpnStatusOn() bool {
	return h.cfg.VPNStatusFile != "" || h.cfg.GateLogs != nil && h.cfg.GateLogs.WGStatus != nil
}

// readWGStatus is vpn.ReadStatus on wg's status: the file, or (HA) the
// document wg's port answers, parsed the same way.
func (h *Hub) readWGStatus(now time.Time) (*vpn.Status, error) {
	if h.cfg.GateLogs != nil && h.cfg.GateLogs.WGStatus != nil {
		ctx, cancel := context.WithTimeout(context.Background(), wgStatusTimeout)
		defer cancel()
		b, err := h.cfg.GateLogs.WGStatus.Status(ctx)
		if err != nil {
			return nil, err
		}
		return vpn.ParseStatus(b, now)
	}
	if h.cfg.VPNStatusFile == "" {
		return nil, errors.New("no VPN status file is configured")
	}
	return vpn.ReadStatus(h.cfg.VPNStatusFile, now)
}
