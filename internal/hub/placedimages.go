package hub

import (
	"context"
	"errors"
	"log"
	"slices"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/agentapi"
	"github.com/portcullis/hub/internal/docker"
	agentrt "github.com/portcullis/hub/internal/runtime/agent"
	"github.com/portcullis/hub/internal/templates"
)

// Pull failure categories (the only thing logged for an override).
const (
	pullArchMismatch = "arch mismatch"
	pullRefused      = "pull refused"
	pullFailed       = "pull failed"
	pullRateLimited  = "rate limited"
)

// pullFailureCategory classifies a pre-pull failure without keeping any
// of its text.
func pullFailureCategory(err error) string {
	if noPlatform(err) {
		return pullArchMismatch
	}
	status := 0
	var ae *agentrt.Error
	if errors.As(err, &ae) {
		status = ae.AgentStatus
	}
	switch {
	case status == 429:
		return pullRateLimited
	case status == 400 || status == 401 || status == 403 || status == 404:
		return pullRefused
	}
	return pullFailed
}

// noPlatform: a worker's pull failed for want of an image for its
// platform — the agent's error_kind only, never its words (final review
// B2: a worker's message is untrusted and masked anyway).
func noPlatform(err error) bool {
	var ae *agentrt.Error
	return errors.As(err, &ae) && ae.Kind == agentapi.ErrorKindNoPlatform
}

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
	svcOf := map[string]string{} // an overridden ref → its first service (the log names it, never the ref)
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
			svcOf[s.Image] = name
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
				// The ref and the agent's words may carry a setting's value:
				// the log has the instance, server, service and a category only.
				cat := pullFailureCategory(err)
				log.Printf("placement: pre-pull of service %s's overridden image of %s on %s: %s", svcOf[ref], t.ID, server, cat)
				arch := ""
				if inf := h.serverInfo(server); inf != nil {
					arch = untrusted(inf.Arch, 20)
				}
				if cat == pullArchMismatch {
					return statusErr(409, "an overridden image of %s has no %s image", t.ID, arch)
				}
				return statusErr(409, "pulling an overridden image of %s on %s failed", t.ID, h.serverName(server))
			}
		}
	}
	h.overridePreflight.Store(t.ID, key)
	return nil
}
