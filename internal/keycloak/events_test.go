package keycloak_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/keycloak/kctest"
)

// TestEnsureEventsConfigKeepsListeners (contract §8 "Keycloak's events
// config"): the Hub writes eventsEnabled, the two event types and the
// expiration, and keeps the listeners and every other field as read; an
// equal config isn't written again.
func TestEnsureEventsConfigKeepsListeners(t *testing.T) {
	ctx := context.Background()
	kc := kctest.New(t)
	c := keycloak.New(kc.HTTP.URL, "admin", "admin")
	kc.With(func() {
		kc.EventsConfig = map[string]any{"eventsEnabled": false, "eventsListeners": []any{"jboss-logging", "x"},
			"enabledEventTypes": []any{"REGISTER"}, "adminEventsEnabled": true, "adminEventsDetailsEnabled": true}
	})
	if err := c.EnsureEventsConfig(ctx, 90); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	kc.With(func() { got = kc.EventsConfig })
	want := map[string]any{"eventsEnabled": true, "eventsListeners": []any{"jboss-logging", "x"},
		"enabledEventTypes": []any{"LOGIN", "LOGIN_ERROR"}, "eventsExpiration": float64(90 * 86400),
		"adminEventsEnabled": true, "adminEventsDetailsEnabled": true}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("events config = %v\nwant %v", got, want)
	}
	if n := kc.CountCalls("PUT /admin/realms/portcullis/events/config"); n != 1 {
		t.Errorf("%d PUTs, want 1", n)
	}
	// Already right: read, not written.
	if err := c.EnsureEventsConfig(ctx, 90); err != nil {
		t.Fatal(err)
	}
	if n := kc.CountCalls("PUT /admin/realms/portcullis/events/config"); n != 1 {
		t.Errorf("an equal config was written again (%d PUTs)", n)
	}
	// A new history length is written.
	if err := c.EnsureEventsConfig(ctx, 365); err != nil {
		t.Fatal(err)
	}
	kc.With(func() { got = kc.EventsConfig })
	if got["eventsExpiration"] != float64(365*86400) || !reflect.DeepEqual(got["eventsListeners"], []any{"jboss-logging", "x"}) {
		t.Errorf("after 365: %v", got)
	}
	// Refusals: no history length; Keycloak failing.
	if err := c.EnsureEventsConfig(ctx, 0); err == nil {
		t.Error("0 days accepted")
	}
	kc.SetFailPrefix("PUT /admin/realms/portcullis/events")
	if err := c.EnsureEventsConfig(ctx, 30); err == nil {
		t.Error("a failed PUT was not reported")
	}
	kc.SetFailPrefix("GET /admin/realms/portcullis/events")
	if err := c.EnsureEventsConfig(ctx, 30); err == nil {
		t.Error("a failed GET was not reported")
	}
}
