package settings

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/portcullis/hub/internal/templates"
)

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

// HookReport is a hook's optional report line (contract §13.8): findings
// and per-person folder metadata. Read and validated as untrusted input
// (F32); subjects not in the population are dropped.
type HookReport struct {
	Version  int           `json:"version"`
	Findings []HookFinding `json:"findings,omitempty"`
	Folders  []HookFolder  `json:"folders,omitempty"`
}

// HookFinding is one finding (§13.8): doctor-like observations the hook
// reports (a former account, a wrong owner, a refused share name, an
// unwritable folder).
type HookFinding struct {
	Code     string `json:"code"`             // former_account, wrong_owner, name_refused, owner_unwritable
	Severity string `json:"severity"`         // problem, warning, info
	Subject  string `json:"subject"`          // username or share name
	Message  string `json:"message"`          // one line, ≤ 200 runes
	Option   string `json:"option,omitempty"` // the path option key
	UID      *int64 `json:"uid,omitempty"`    // the folder's owner uid
	Former   *bool  `json:"former,omitempty"` // true when the owner isn't the person's current id
}

// HookFolder is one per-person folder's metadata (§13.8): option, name
// (the top-level directory, a username), uid, bytes and whether it's a
// former account's.
type HookFolder struct {
	Option string `json:"option"` // the path option key
	Name   string `json:"name"`   // the directory (username)
	UID    int64  `json:"uid"`    // the folder's owner uid
	Former bool   `json:"former"` // true when uid isn't the person's current id
	Bytes  *int64 `json:"bytes"`  // the folder size in bytes, or null
}

// ParseHookReport parses a hook's report line (§13.8, F32): exactly one
// PORTCULLIS-REPORT line, strict JSON, version 1, validated as untrusted
// input.
func ParseHookReport(output []byte) (*HookReport, error) {
	const (
		prefix      = "PORTCULLIS-REPORT "
		maxSize     = 64 * 1024
		maxFindings = 500
		maxFolders  = 500
		maxRunes    = 200
	)

	// Find the report line
	lines := bytes.Split(output, []byte{'\n'})
	var reportLine []byte
	count := 0
	for _, line := range lines {
		if bytes.HasPrefix(line, []byte(prefix)) {
			count++
			reportLine = line
		}
	}

	if count == 0 {
		return nil, errors.New("no PORTCULLIS-REPORT line")
	}
	if count > 1 {
		return nil, errors.New("multiple PORTCULLIS-REPORT lines")
	}

	// Check size
	if len(reportLine) > maxSize {
		return nil, fmt.Errorf("report line exceeds 64 KiB")
	}

	// Extract JSON
	jsonData := reportLine[len(prefix):]

	// Decode with DisallowUnknownFields
	dec := json.NewDecoder(bytes.NewReader(jsonData))
	dec.DisallowUnknownFields()

	var rep HookReport
	if err := dec.Decode(&rep); err != nil {
		if strings.Contains(err.Error(), "unknown field") {
			return nil, fmt.Errorf("unknown field in report JSON")
		}
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	// Validate version
	if rep.Version != 1 {
		return nil, fmt.Errorf("version must be 1, got %d", rep.Version)
	}

	// Check list sizes
	if len(rep.Findings) > maxFindings {
		return nil, fmt.Errorf("at most 500 findings, got %d", len(rep.Findings))
	}
	if len(rep.Folders) > maxFolders {
		return nil, fmt.Errorf("at most 500 folders, got %d", len(rep.Folders))
	}

	// Validate findings
	validCodes := map[string]bool{
		"former_account":   true,
		"wrong_owner":      true,
		"name_refused":     true,
		"owner_unwritable": true,
	}
	validSeverities := map[string]bool{
		"problem": true,
		"warning": true,
		"info":    true,
	}

	for i, f := range rep.Findings {
		if !validCodes[f.Code] {
			return nil, fmt.Errorf("findings[%d]: invalid code %q", i, f.Code)
		}
		if !validSeverities[f.Severity] {
			return nil, fmt.Errorf("findings[%d]: invalid severity %q", i, f.Severity)
		}
		if err := checkStringField("subject", f.Subject, maxRunes); err != nil {
			return nil, fmt.Errorf("findings[%d]: %w", i, err)
		}
		if err := checkStringField("message", f.Message, maxRunes); err != nil {
			return nil, fmt.Errorf("findings[%d]: %w", i, err)
		}
		if f.Option != "" {
			if err := checkStringField("option", f.Option, maxRunes); err != nil {
				return nil, fmt.Errorf("findings[%d]: %w", i, err)
			}
		}
	}

	// Validate folders
	for i, f := range rep.Folders {
		if err := checkStringField("option", f.Option, maxRunes); err != nil {
			return nil, fmt.Errorf("folders[%d]: %w", i, err)
		}
		if err := checkStringField("name", f.Name, maxRunes); err != nil {
			return nil, fmt.Errorf("folders[%d]: %w", i, err)
		}
	}

	return &rep, nil
}

// checkStringField validates a string field: one line, ≤ maxRunes, no
// control characters.
func checkStringField(name, value string, maxRunes int) error {
	if utf8.RuneCountInString(value) > maxRunes {
		return fmt.Errorf("%s: at most %d runes, got %d", name, maxRunes, utf8.RuneCountInString(value))
	}
	if strings.ContainsAny(value, "\n\r\t") || templates.HasControlChars(value) {
		return fmt.Errorf("%s: control characters not allowed", name)
	}
	return nil
}
