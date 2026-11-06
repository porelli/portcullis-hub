// Package aigate is the Hub's side of the files it writes for core's
// mcp-gate (integration contract §15.4): mcp-gate.json (resources,
// populations, limits) and mcp-credentials.json (per-person app
// credentials and caller secrets, age-encrypted to the gate's recipient).
//
// The types, the strict decoding and every validation rule mirror the
// gate's decoder (core mcp-gate/internal/config: config.go, strict.go),
// which refuses the whole file on any violation. The Hub validates with
// the same rules before every write (WriteFile, WriteCredFile), so it
// never publishes a file the gate would refuse; both sides commit the
// contract's example vector (testdata/) and re-encode it byte for byte.
//
// No Hub import: the package knows nothing about state or templates
// beyond the T8 name helpers.
package aigate

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/fsutil"
)

// Names of the files in the Hub's data directory (next to the policy
// file).
const (
	GateFileName  = "mcp-gate.json"
	CredsFileName = "mcp-credentials.json"
)

// FileMode: 0640, group 10001 (the Hub's gid; the gate has group_add
// 10001 only).
const FileMode = 0o640

// SupportedProtocols are the MCP versions the gate speaks (§15.3).
var SupportedProtocols = []string{"2025-06-18", "2025-11-25", "2026-07-28"}

// Resource kinds (§15.1).
const (
	KindCompanion = "companion"
	KindAggregate = "aggregate"
	KindAdmin     = "portcullis_admin"
	KindPeople    = "portcullis_people"
)

// Fixed resource labels (§15.1 resource_name).
const (
	LabelAggregate = "All my apps"
	LabelAdmin     = "Portcullis (admin)"
	LabelPeople    = "Portcullis"
)

// Identity modes as the gate file names them.
const (
	IdentityAppToken = "app_token"
	IdentityHeaders  = "identity_headers"
	IdentityNone     = "none"
)

// Companion modes.
const (
	ModeReadOnly  = "read_only"
	ModeReadWrite = "read_write"
)

// Credential states (§15.4).
const StateActive, StateRevoking = "active", "revoking"

// Fixed limits of this release (§15.4).
const (
	FixedMaxRequestBytes  = 8388608
	FixedMaxResultBytes   = 16777216
	FixedUpstreamTimeoutS = 120
	// MaxFanout: the gate refuses a larger limits.fanout.
	MaxFanout = 4
)

// ACRLoA is the realm's acr → LoA map (core realm acr.loa.map, §15.2).
func ACRLoA() map[string]int { return map[string]int{"public": 0, "pwd": 1, "hwk": 2, "mtls": 3} }

// File is mcp-gate.json (§15.4). Field order is the file's key order.
type File struct {
	Version        int            `json:"version"`
	Enabled        bool           `json:"enabled"`
	Issuer         string         `json:"issuer"`
	MainDomain     string         `json:"main_domain"`
	Clients        []string       `json:"clients"`
	AllowedOrigins []string       `json:"allowed_origins"`
	ACRLoA         map[string]int `json:"acr_loa"`
	Limits         Limits         `json:"limits"`
	CoreHosts      []string       `json:"core_hosts"`
	Resources      []Resource     `json:"resources"`
}

// Limits (§15.9). All positive.
type Limits struct {
	ResourceRPM          int   `json:"resource_rpm"`
	ResourceBurst        int   `json:"resource_burst"`
	PersonRPM            int   `json:"person_rpm"`
	ToolCallsRPM         int   `json:"tool_calls_rpm"`
	ConfirmationsPerHour int   `json:"confirmations_per_hour"`
	MintsPerMinute       int   `json:"mints_per_minute"`
	Fanout               int   `json:"fanout"`
	MaxRequestBytes      int64 `json:"max_request_bytes"`
	MaxResultBytes       int64 `json:"max_result_bytes"`
	UpstreamTimeoutS     int   `json:"upstream_timeout_s"`
}

// Resource is one OAuth protected resource (§15.1, §15.4).
type Resource struct {
	URL        string            `json:"url"`
	Scope      string            `json:"scope"`
	Clients    []string          `json:"clients"`
	Kind       string            `json:"kind"`
	Instance   string            `json:"instance"`
	Companion  string            `json:"companion"`
	Label      string            `json:"label"`
	Host       string            `json:"host"`
	Hosts      []string          `json:"hosts"`
	AppURL     string            `json:"app_url"`
	MinLoA     int               `json:"min_loa"`
	Upstream   string            `json:"upstream"`
	Protocol   []string          `json:"protocol"`
	Mode       string            `json:"mode"`
	Identity   Identity          `json:"identity"`
	Tools      Tools             `json:"tools"`
	Aggregate  bool              `json:"aggregate"`
	Population []string          `json:"population"`
	Expiring   map[string]Time   `json:"expiring"`
	People     map[string]Person `json:"people,omitempty"`
}

// Identity is how the gate presents the person upstream (§15.5).
type Identity struct {
	Mode      string `json:"mode"`
	Header    string `json:"header"`
	Format    string `json:"format"`
	BasicUser string `json:"basic_user"`
	SecretRef string `json:"secret_ref"`
}

// Tools are the template's tool patterns (§3.2), in the template's order.
type Tools struct {
	Writes  []string `json:"writes"`
	Confirm []string `json:"confirm"`
	Never   []string `json:"never"`
}

// Person is what an identity_headers companion learns about a member.
type Person struct {
	Email  string   `json:"email"`
	Groups []string `json:"groups"`
}

// CredFile is mcp-credentials.json (§15.4).
type CredFile struct {
	Version       int            `json:"version"`
	Credentials   []Credential   `json:"credentials"`
	CallerSecrets []CallerSecret `json:"caller_secrets"`
}

// Credential is one per-person credential; Age is the armored ciphertext
// ("" while revoking).
type Credential struct {
	Instance  string `json:"instance"`
	Companion string `json:"companion"`
	User      string `json:"user"`
	ID        string `json:"id"`
	MintedAt  Time   `json:"minted_at"`
	State     string `json:"state"`
	Age       string `json:"age"`
}

// CallerSecret is one identity_headers companion's caller secret.
type CallerSecret struct {
	Ref string `json:"ref"`
	Age string `json:"age"`
}

// Time is an RFC 3339 UTC ("Z") timestamp (the gate's config.Time).
type Time struct{ time.Time }

// At is t as the files carry it: UTC, whole seconds (truncated: an
// expiry never moves later).
func At(t time.Time) Time { return Time{t.UTC().Truncate(time.Second)} }

// UnmarshalJSON accepts only RFC 3339 strings in UTC.
func (t *Time) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("not a timestamp string")
	}
	if !strings.HasSuffix(s, "Z") {
		return fmt.Errorf("timestamp not in UTC")
	}
	tt, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return fmt.Errorf("not an RFC 3339 timestamp")
	}
	t.Time = tt.UTC()
	return nil
}

// DecodeFile decodes and validates mcp-gate.json strictly.
func DecodeFile(b []byte) (*File, error) {
	var f File
	if err := decodeStrict(b, &f); err != nil {
		return nil, err
	}
	if err := f.Validate(); err != nil {
		return nil, err
	}
	return &f, nil
}

// DecodeCredFile decodes and validates mcp-credentials.json strictly.
// Errors name fields and entry indexes, never values.
func DecodeCredFile(b []byte) (*CredFile, error) {
	var c CredFile
	if err := decodeStrict(b, &c); err != nil {
		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Encode is the file in the contract's form: Go's indented JSON, two
// spaces, a trailing newline (the gate's Encode is byte-identical).
func (f *File) Encode() ([]byte, error) { return encode(f) }

// Encode is the credentials file in the contract's form.
func (c *CredFile) Encode() ([]byte, error) { return encode(c) }

func encode(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// WriteJSON writes v in the contract's form atomically (temp file in the
// same directory, fsync, rename) with mode 0640.
func WriteJSON(path string, v any) error {
	b, err := encode(v)
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(path, b, FileMode)
}

// WriteFile validates f with the gate's rules, then writes it; an
// invalid file is never written (the previous one stays).
func WriteFile(path string, f *File) error {
	if err := f.Validate(); err != nil {
		return fmt.Errorf("%s: %w", GateFileName, err)
	}
	return WriteJSON(path, f)
}

// WriteCredFile validates c with the gate's rules, then writes it.
func WriteCredFile(path string, c *CredFile) error {
	if err := c.Validate(); err != nil {
		return fmt.Errorf("%s: %w", CredsFileName, err)
	}
	return WriteJSON(path, c)
}
