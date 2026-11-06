package hub

import (
	"encoding/json"
	"testing"

	"github.com/portcullis/hub/internal/directory"
)

// save is SaveSettings as admin, the error only.
func (h *Hub) save(id string, u SettingsUpdate) error {
	_, err := h.SaveSettings(id, u, directory.Human("admin"))
	return err
}

// vals builds option values from key, value pairs; a value is any JSON
// value (strings are marshalled as JSON strings, nil as null).
func vals(kv ...any) map[string]json.RawMessage {
	out := map[string]json.RawMessage{}
	for i := 0; i+1 < len(kv); i += 2 {
		b, err := json.Marshal(kv[i+1])
		if err != nil {
			panic(err)
		}
		out[kv[i].(string)] = b
	}
	return out
}

var _ = testing.Short
