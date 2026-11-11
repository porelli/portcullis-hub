package keycloak

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
)

// EventTypes are the user events the Hub has Keycloak store (contract §8
// "Keycloak's events config"): the sign-in history's source (§8.2).
var EventTypes = []string{"LOGIN", "LOGIN_ERROR"}

// eventsConfigPath is the realm's events config.
func (c *Client) eventsConfigPath() string {
	return c.BaseURL + "/admin/realms/" + Realm + "/events/config"
}

// EnsureEventsConfig makes the realm store LOGIN and LOGIN_ERROR events
// for historyDays days (contract §8 "Keycloak's events config"): it reads
// the config and, when it differs, writes it back with eventsEnabled true,
// enabledEventTypes [LOGIN, LOGIN_ERROR] and eventsExpiration
// historyDays × 86400 seconds. Every other field — eventsListeners and
// the admin-events switches included — is written back as it was read.
func (c *Client) EnsureEventsConfig(ctx context.Context, historyDays int) error {
	if historyDays < 1 {
		return fmt.Errorf("events config: history of %d days", historyDays)
	}
	tok, err := c.token(ctx)
	if err != nil {
		return err
	}
	resp, err := c.api().GetRequestWithBearerAuth(ctx, tok).Get(c.eventsConfigPath())
	if err != nil {
		return fmt.Errorf("read the events config: %w", err)
	}
	if resp.IsError() {
		return &HTTPError{Op: "read the events config", Status: resp.StatusCode()}
	}
	cfg := map[string]json.RawMessage{}
	if err := json.Unmarshal(resp.Body(), &cfg); err != nil || cfg == nil {
		return fmt.Errorf("read the events config: not a JSON object")
	}
	var cur struct {
		Enabled    bool     `json:"eventsEnabled"`
		Types      []string `json:"enabledEventTypes"`
		Expiration int64    `json:"eventsExpiration"`
	}
	// A field of another type just counts as different.
	_ = json.Unmarshal(resp.Body(), &cur)
	want := int64(historyDays) * 86400
	if cur.Enabled && slices.Equal(cur.Types, EventTypes) && cur.Expiration == want {
		return nil
	}
	cfg["eventsEnabled"] = json.RawMessage("true")
	types, _ := json.Marshal(EventTypes)
	cfg["enabledEventTypes"] = types
	cfg["eventsExpiration"] = json.RawMessage(fmt.Sprint(want))
	resp, err = c.api().GetRequestWithBearerAuth(ctx, tok).SetBody(cfg).Put(c.eventsConfigPath())
	if err != nil {
		return fmt.Errorf("write the events config: %w", err)
	}
	if resp.IsError() {
		return &HTTPError{Op: "write the events config", Status: resp.StatusCode()}
	}
	return nil
}
