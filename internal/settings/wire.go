package settings

// The documents the Hub hands to apps (contract §13.7–13.8): data files,
// their secrets files and hook stdin.

// Wire format versions.
const (
	DataFileVersion  = 1
	HookInputVersion = 1
)

// GroupRecordOut is one group record as delivered: the group's name and
// the rendered value.
type GroupRecordOut struct {
	Group string `json:"group"`
	Value any    `json:"value"`
}

// EntryOut is one person-entered value (call 32): the lowercase user and
// the rendered value.
type EntryOut struct {
	User  string `json:"user"`
	Value any    `json:"value"`
}

// DataFileDoc is a data file (<name>.json). Every section is always an
// object (never null).
type DataFileDoc struct {
	Version  int                         `json:"version"`
	Instance string                      `json:"instance"`
	Values   map[string]any              `json:"values"`
	People   map[string]map[string]any   `json:"people"`
	Groups   map[string][]GroupRecordOut `json:"groups"`
	// Entries: person-entered values per field, sorted by user (Task 15A).
	Entries map[string][]EntryOut `json:"entries"`
}

// NewDataFileDoc is an empty data file of instance.
func NewDataFileDoc(instance string) DataFileDoc {
	return DataFileDoc{Version: DataFileVersion, Instance: instance, Values: map[string]any{},
		People: map[string]map[string]any{}, Groups: map[string][]GroupRecordOut{}, Entries: map[string][]EntryOut{}}
}

// SecretsFileDoc is a data file's secrets file (<name>.secrets.json):
// the secret options' values by key.
type SecretsFileDoc struct {
	Version  int               `json:"version"`
	Instance string            `json:"instance"`
	Secrets  map[string]string `json:"secrets"`
}

// HookInput is a hook's stdin: the full desired state, never a diff.
type HookInput struct {
	DataFileDoc
	Trigger string            `json:"trigger"`
	Secrets map[string]string `json:"secrets"`
}
