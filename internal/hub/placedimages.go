package hub

import (
	"context"
	"log"
	"slices"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/templates"
)

// placedImages: every image a worker instance's rendered project runs
// (every profile; the custom compose override, the settings and the
// instance's .env applied — an "override" of the template's image) is pinned
// by digest — a worker never pulls a mutable tag (contract §11.7, at
// every prepareUp: an override can change after create); 409 before
// anything is sent. An image that isn't the template's own (an
// override) is named by its service, never echoed (it may come from a
// setting's value). The
// overridden pinned refs are preflight-pulled when that set changed since
// the last start, so a missing architecture is still refused early.
func (h *Hub) placedImages(ctx context.Context, t *templates.Template, server string) error {
	proj, err := h.loadRendered(ctx, t)
	if err != nil {
		return statusErr(500, "load %s's project: %v", t.ID, err)
	}
	raw := templates.ServiceImages(t.ReadCompose())
	var refEnv map[string]string
	if inf := h.serverInfo(server); inf != nil {
		refEnv = imageRefEnv(h, inf)
	}
	var overridden []string
	names := make([]string, 0, len(proj.Services))
	for name := range proj.Services {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		s := proj.Services[name]
		if s.Image == "" || s.Build != nil {
			continue
		}
		own, ok := expandRef(raw[name], refEnv)
		own = strings.TrimSpace(own)
		isOwn := ok && raw[name] != "" && own == s.Image
		if !docker.DigestRef(s.Image) {
			if isOwn {
				return statusErr(409, "image %s isn't pinned by digest: templates must pin images to run on a worker", raw[name])
			}
			return statusErr(409, "image of service %s (an override) isn't pinned by digest: templates must pin images to run on a worker", name)
		}
		if !isOwn && !slices.Contains(overridden, s.Image) {
			overridden = append(overridden, s.Image)
		}
	}
	key := server + "\x00" + strings.Join(overridden, "\x00")
	if prev, ok := h.overridePreflight.Load(t.ID); ok && prev == key {
		return nil
	}
	if len(overridden) > 0 {
		rt, err := h.rtForServer(server)
		if err != nil {
			return err
		}
		pre, ok := rt.(preflighter)
		if !ok {
			return statusErr(409, "%s can't pre-pull images", h.serverName(server))
		}
		pctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
		defer cancel()
		for _, ref := range overridden {
			if err := pre.PreflightPull(pctx, ref); err != nil {
				log.Printf("placement: pre-pull of an overridden image of %s on %s failed: %s", t.ID, server, clip(err.Error(), 300))
				msg := strings.ToLower(err.Error())
				arch := ""
				if inf := h.serverInfo(server); inf != nil {
					arch = inf.Arch
				}
				if strings.Contains(msg, "no matching manifest") || strings.Contains(msg, "platform") || strings.Contains(msg, "architecture") {
					return statusErr(409, "an overridden image of %s has no %s image", t.ID, arch)
				}
				return statusErr(409, "pulling an overridden image of %s on %s failed", t.ID, h.serverName(server))
			}
		}
	}
	h.overridePreflight.Store(t.ID, key)
	return nil
}
