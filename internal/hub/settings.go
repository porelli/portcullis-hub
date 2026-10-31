package hub

import (
	"bytes"
	"context"
	"log"
	"net"
	"os"
	"strconv"

	"gopkg.in/yaml.v3"

	"github.com/portcullis/hub/internal/fsutil"
	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/templates"
)

// AppSettingsView is the GET /api/templates/settings/<id> payload.
type AppSettingsView struct {
	Definitions     []templates.Setting `json:"definitions"`
	Ports           []templates.Port    `json:"ports"`
	Values          map[string]string   `json:"values"`
	EffectivePolicy policy.AuthPolicy   `json:"effective_policy"`
	DefaultPolicy   policy.AuthPolicy   `json:"default_policy"`
	SafetyScore     float64             `json:"safety_score"`
	AuthPolicy      *policy.AuthPolicy  `json:"auth_policy,omitempty"`
}

// AppSettings returns an app's settings and policy.
func (h *Hub) AppSettings(id string) (*AppSettingsView, error) {
	t := h.Template(id)
	if t == nil {
		return nil, ErrNotFound
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	eff := h.st.ResolvePolicy(id)
	v := &AppSettingsView{
		Definitions:     t.Manifest.Settings,
		Ports:           t.Manifest.Ports,
		Values:          h.st.Settings[id],
		EffectivePolicy: eff,
		DefaultPolicy:   h.st.DefaultPolicy,
		SafetyScore:     policy.SafetyScore(eff),
	}
	if p, ok := h.st.AuthPolicies[id]; ok {
		v.AuthPolicy = &p
	}
	return v, nil
}

// ValidateSettings checks user-supplied settings against a manifest: every
// key/value ends up in the per-app .env and possibly the compose override.
func ValidateSettings(t *templates.Template, values map[string]string) error {
	for k, v := range values {
		if !templates.EnvKeyRe.MatchString(k) {
			return statusErr(400, "invalid setting key %q", k)
		}
		if templates.HasControlChars(v) {
			return statusErr(400, "setting %s contains control characters", k)
		}
	}
	for _, st := range t.Manifest.Settings {
		if v := values[st.Key]; v != "" && st.Type == "path" {
			if err := templates.ValidatePathSetting(v); err != nil {
				return statusErr(400, "setting %s: %v", st.Key, err)
			}
		}
	}
	for _, p := range t.Manifest.Ports {
		if b := values[p.Key+"_BIND"]; b != "" && net.ParseIP(b) == nil {
			return statusErr(400, "bind address for %s must be an IP address", p.Key)
		}
		v, ok := values[p.Key]
		if !ok {
			continue
		}
		if v == "" {
			if p.Required {
				return statusErr(400, "port %s is required", p.Key)
			}
			continue
		}
		if n, err := strconv.Atoi(v); err != nil || n < 1 || n > 65535 {
			return statusErr(400, "port %s must be 1-65535", p.Key)
		}
	}
	return nil
}

// SettingsUpdate is a PUT /api/templates/settings/<id> request.
type SettingsUpdate struct {
	Values  map[string]string
	Policy  *policy.AuthPolicy // nil = unchanged; normalised by SaveSettings
	Inherit bool               // drop the per-app policy override
}

// SaveSettings validates and stores an app's settings (and optionally its
// policy) in one state change, rewrites its override/.env and, if enabled,
// queues a restart.
func (h *Hub) SaveSettings(id string, u SettingsUpdate) error {
	t := h.Template(id)
	if t == nil {
		return ErrNotFound
	}
	if u.Values == nil {
		u.Values = map[string]string{}
	}
	if err := ValidateSettings(t, u.Values); err != nil {
		return err
	}

	h.mu.Lock()
	prev, hadPrev := h.st.Settings[id]
	h.st.Settings[id] = u.Values
	live := h.findLocked(id)
	enabled := live != nil && live.Enabled
	if enabled {
		if err := h.checkPortCollisionsLocked(t); err != nil {
			if hadPrev {
				h.st.Settings[id] = prev
			} else {
				delete(h.st.Settings, id)
			}
			h.mu.Unlock()
			return err
		}
	}
	policyChanged := false
	if u.Inherit {
		if _, had := h.st.AuthPolicies[id]; had {
			delete(h.st.AuthPolicies, id)
			policyChanged = true
		}
	} else if u.Policy != nil {
		h.st.AuthPolicies[id] = policy.Normalize(*u.Policy)
		policyChanged = true
	}
	h.saveLocked()
	effective := h.st.ResolvePolicy(id)
	// The override reads state (policy → TLS tier): render under the lock.
	overrideErr := h.generateOverrideLocked(t, u.Values)
	h.mu.Unlock()
	if overrideErr != nil {
		return statusErr(500, "settings saved but override generation failed: %v", overrideErr)
	}

	// text/boolean/select settings go into the .env — including empty
	// values, so clearing a field actually clears it.
	envPath := h.envPath(id)
	for _, st := range t.Manifest.Settings {
		if st.Type != "text" && st.Type != "boolean" && st.Type != "select" {
			continue
		}
		if v, ok := u.Values[st.Key]; ok {
			if err := setEnvVar(envPath, st.Key, v); err != nil {
				return statusErr(500, "failed to write env: %v", err)
			}
		}
	}

	if policyChanged {
		h.writePolicyLogged()
		if h.idp != nil {
			acr := policy.ACR(effective)
			for _, c := range t.Manifest.Clients {
				if err := h.idp.UpdateClientACR(context.Background(), h.clientSpec(t, c, acr)); err != nil {
					log.Printf("auth-policy: keycloak client %s update failed: %v", c.ClientID, err)
				}
			}
		}
	}
	if enabled {
		go h.Restart(*t)
	}
	return nil
}

// DefaultPolicy returns the global default policy.
func (h *Hub) DefaultPolicy() policy.AuthPolicy {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.st.DefaultPolicy
}

// SetDefaultPolicy stores a new global default and, if it changed,
// propagates it in the background. Returns whether it changed.
func (h *Hub) SetDefaultPolicy(p policy.AuthPolicy) bool {
	norm := policy.Normalize(p)
	h.mu.Lock()
	changed := !policy.Same(h.st.DefaultPolicy, norm)
	h.st.DefaultPolicy = norm
	h.saveLocked()
	h.mu.Unlock()
	if !changed {
		return false
	}
	h.writePolicyLogged()
	go h.applyDefaultPolicy()
	return true
}

// applyDefaultPolicy propagates a changed default to every enabled app that
// inherits it: regenerate overrides (TLS tier), push the Keycloak acr, and
// recreate containers whose labels changed.
func (h *Hub) applyDefaultPolicy() {
	h.defaultPolicyMu.Lock()
	defer h.defaultPolicyMu.Unlock()
	type job struct {
		t       templates.Template
		restart bool
	}
	var jobs []job
	h.mu.Lock()
	for _, id := range h.st.Enabled {
		if _, override := h.st.AuthPolicies[id]; override {
			continue
		}
		t := h.findLocked(id)
		if t == nil {
			continue
		}
		before, _ := os.ReadFile(h.overridePath(id))
		if err := h.generateOverrideLocked(t, h.st.Settings[id]); err != nil {
			log.Printf("default-policy: override for %s failed: %v", id, err)
			continue
		}
		after, _ := os.ReadFile(h.overridePath(id))
		changed := !bytes.Equal(before, after)
		if changed || len(t.Manifest.Clients) > 0 {
			jobs = append(jobs, job{t: *t, restart: changed})
		}
	}
	acr := policy.ACR(h.st.DefaultPolicy)
	h.mu.Unlock()

	for _, j := range jobs {
		if h.idp != nil {
			for _, c := range j.t.Manifest.Clients {
				if err := h.idp.UpdateClientACR(context.Background(), h.clientSpec(&j.t, c, acr)); err != nil {
					log.Printf("default-policy: keycloak client %s update failed: %v", c.ClientID, err)
				}
			}
		}
		if j.restart {
			h.Restart(j.t)
		}
	}
}

// ── Expert mode ──────────────────────────────────────────

// ComposeFiles returns an app's compose.yml and generated override.
func (h *Hub) ComposeFiles(id string) (compose, override string, err error) {
	t := h.Template(id)
	if t == nil {
		return "", "", ErrNotFound
	}
	data, err := os.ReadFile(t.ComposePath())
	if err != nil {
		return "", "", statusErr(404, "compose.yml not found")
	}
	ov, _ := os.ReadFile(h.overridePath(id))
	return string(data), string(ov), nil
}

// SaveComposeFiles replaces an app's compose.yml (and override; "" removes
// it) after checking both parse as YAML.
func (h *Hub) SaveComposeFiles(id, compose, override string) error {
	t := h.Template(id)
	if t == nil {
		return ErrNotFound
	}
	var check interface{}
	if err := yaml.Unmarshal([]byte(compose), &check); err != nil {
		return statusErr(400, "Invalid YAML: %v", err)
	}
	if override != "" {
		if err := yaml.Unmarshal([]byte(override), &check); err != nil {
			return statusErr(400, "Invalid override YAML: %v", err)
		}
	}
	if err := fsutil.WriteFileAtomic(t.ComposePath(), []byte(compose), 0644); err != nil {
		return statusErr(500, "Failed to write: %v", err)
	}
	if override != "" {
		if err := fsutil.WriteFileAtomic(h.overridePath(id), []byte(override), 0600); err != nil {
			return statusErr(500, "Failed to write override: %v", err)
		}
	} else {
		os.Remove(h.overridePath(id))
	}
	// Host() rules may have changed → refresh subdomain policy/groups.
	h.writePolicyLogged()
	return nil
}

// Env returns an app's .env variables and compose service names.
func (h *Hub) Env(id string) (map[string]string, []string, error) {
	t := h.Template(id)
	if t == nil {
		return nil, nil, ErrNotFound
	}
	return readEnvFile(h.envPath(id)), templates.Services(t.ReadCompose()), nil
}

// SaveEnv sets variables in an app's .env.
func (h *Hub) SaveEnv(id string, vars map[string]string) error {
	if h.Template(id) == nil {
		return ErrNotFound
	}
	for k, v := range vars {
		if !templates.EnvKeyRe.MatchString(k) || templates.HasControlChars(v) {
			return statusErr(400, "invalid variable %q (keys: [A-Za-z_][A-Za-z0-9_]*, values: no newlines)", k)
		}
	}
	for k, v := range vars {
		if err := setEnvVar(h.envPath(id), k, v); err != nil {
			return statusErr(500, "failed to write env: %v", err)
		}
	}
	return nil
}
