package settings

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestParseHookReport checks the strict parser (F32).
func TestParseHookReport(t *testing.T) {
	tests := []struct {
		name    string
		output  string
		wantErr string
	}{
		{
			name: "valid empty report",
			output: `PORTCULLIS-REPORT {"version": 1}
other output`,
			wantErr: "",
		},
		{
			name: "valid with findings and folders",
			output: `PORTCULLIS-REPORT {"version": 1, "findings": [{"code": "former_account", "severity": "warning", "subject": "alice", "message": "alice's Time Machine folder belongs to a former account (uid 20023)", "uid": 20023, "former": true}], "folders": [{"option": "storage", "name": "alice", "uid": 20000, "former": false, "bytes": 107374182400}]}
`,
			wantErr: "",
		},
		{
			name:    "no report line",
			output:  `some output`,
			wantErr: "no PORTCULLIS-REPORT line",
		},
		{
			name: "two report lines",
			output: `PORTCULLIS-REPORT {"version": 1}
PORTCULLIS-REPORT {"version": 1}`,
			wantErr: "multiple PORTCULLIS-REPORT lines",
		},
		{
			name:    "too large",
			output:  "PORTCULLIS-REPORT " + strings.Repeat("x", 64*1024),
			wantErr: "exceeds 64 KiB",
		},
		{
			name:    "invalid JSON",
			output:  `PORTCULLIS-REPORT {bad json}`,
			wantErr: "invalid JSON",
		},
		{
			name:    "unknown field",
			output:  `PORTCULLIS-REPORT {"version": 1, "unknown": "field"}`,
			wantErr: "unknown field",
		},
		{
			name:    "wrong version",
			output:  `PORTCULLIS-REPORT {"version": 2}`,
			wantErr: "version must be 1",
		},
		{
			name:    "too many findings",
			output:  "PORTCULLIS-REPORT " + buildReportWithFindings(501),
			wantErr: "at most 500 findings",
		},
		{
			name:    "too many folders",
			output:  "PORTCULLIS-REPORT " + buildReportWithFolders(501),
			wantErr: "at most 500 folders",
		},
		{
			name:    "invalid code",
			output:  `PORTCULLIS-REPORT {"version": 1, "findings": [{"code": "bad_code", "severity": "warning", "subject": "alice", "message": "test"}]}`,
			wantErr: "invalid code",
		},
		{
			name:    "invalid severity",
			output:  `PORTCULLIS-REPORT {"version": 1, "findings": [{"code": "former_account", "severity": "critical", "subject": "alice", "message": "test"}]}`,
			wantErr: "invalid severity",
		},
		{
			name:    "subject with newline",
			output:  `PORTCULLIS-REPORT {"version": 1, "findings": [{"code": "former_account", "severity": "warning", "subject": "alice\nbob", "message": "test"}]}`,
			wantErr: "control characters",
		},
		{
			name:    "subject too long",
			output:  `PORTCULLIS-REPORT {"version": 1, "findings": [{"code": "former_account", "severity": "warning", "subject": "` + strings.Repeat("a", 201) + `", "message": "test"}]}`,
			wantErr: "at most 200 runes",
		},
		{
			name:    "message with tab",
			output:  `PORTCULLIS-REPORT {"version": 1, "findings": [{"code": "former_account", "severity": "warning", "subject": "alice", "message": "test\tmessage"}]}`,
			wantErr: "control characters",
		},
		{
			name:    "message too long",
			output:  `PORTCULLIS-REPORT {"version": 1, "findings": [{"code": "former_account", "severity": "warning", "subject": "alice", "message": "` + strings.Repeat("x", 201) + `"}]}`,
			wantErr: "at most 200 runes",
		},
		{
			name:    "option with newline",
			output:  `PORTCULLIS-REPORT {"version": 1, "folders": [{"option": "stor\nage", "name": "alice", "uid": 20000, "former": false}]}`,
			wantErr: "control characters",
		},
		{
			name:    "name too long",
			output:  `PORTCULLIS-REPORT {"version": 1, "folders": [{"option": "storage", "name": "` + strings.Repeat("a", 201) + `", "uid": 20000, "former": false}]}`,
			wantErr: "at most 200 runes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rep, err := ParseHookReport([]byte(tt.output))
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("ParseHookReport: unexpected error: %v", err)
				}
				if rep == nil {
					t.Error("ParseHookReport: got nil, want report")
				}
			} else {
				if err == nil {
					t.Errorf("ParseHookReport: want error containing %q, got nil", tt.wantErr)
				} else if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("ParseHookReport: want error containing %q, got %v", tt.wantErr, err)
				}
			}
		})
	}
}

func buildReportWithFindings(n int) string {
	findings := make([]string, n)
	for i := range findings {
		findings[i] = `{"code": "former_account", "severity": "warning", "subject": "user", "message": "test"}`
	}
	return `{"version": 1, "findings": [` + strings.Join(findings, ",") + `]}`
}

func buildReportWithFolders(n int) string {
	folders := make([]string, n)
	for i := range folders {
		folders[i] = `{"option": "storage", "name": "user", "uid": 20000, "former": false}`
	}
	return `{"version": 1, "folders": [` + strings.Join(folders, ",") + `]}`
}

// TestParseHookReportValidCodes checks all valid codes.
func TestParseHookReportValidCodes(t *testing.T) {
	codes := []string{"former_account", "wrong_owner", "name_refused", "owner_unwritable"}
	for _, code := range codes {
		output := `PORTCULLIS-REPORT {"version": 1, "findings": [{"code": "` + code + `", "severity": "warning", "subject": "alice", "message": "test"}]}`
		_, err := ParseHookReport([]byte(output))
		if err != nil {
			t.Errorf("ParseHookReport with code %q: unexpected error: %v", code, err)
		}
	}
}

// TestParseHookReportValidSeverities checks all valid severities.
func TestParseHookReportValidSeverities(t *testing.T) {
	severities := []string{"problem", "warning", "info"}
	for _, severity := range severities {
		output := `PORTCULLIS-REPORT {"version": 1, "findings": [{"code": "former_account", "severity": "` + severity + `", "subject": "alice", "message": "test"}]}`
		_, err := ParseHookReport([]byte(output))
		if err != nil {
			t.Errorf("ParseHookReport with severity %q: unexpected error: %v", severity, err)
		}
	}
}

// TestHookReportRoundTrip checks that a valid report can be marshaled and parsed.
func TestHookReportRoundTrip(t *testing.T) {
	bytes := int64(1024)
	former := true
	rep := &HookReport{
		Version: 1,
		Findings: []HookFinding{
			{
				Code:     "former_account",
				Severity: "warning",
				Subject:  "alice",
				Message:  "alice's folder belongs to a former account",
				Option:   "storage",
				UID:      &bytes,
				Former:   &former,
			},
		},
		Folders: []HookFolder{
			{
				Option: "storage",
				Name:   "alice",
				UID:    20000,
				Former: false,
				Bytes:  &bytes,
			},
		},
	}

	data, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	output := "PORTCULLIS-REPORT " + string(data)
	parsed, err := ParseHookReport([]byte(output))
	if err != nil {
		t.Fatalf("ParseHookReport: %v", err)
	}

	if parsed.Version != rep.Version {
		t.Errorf("Version: got %d, want %d", parsed.Version, rep.Version)
	}
	if len(parsed.Findings) != len(rep.Findings) {
		t.Errorf("Findings: got %d, want %d", len(parsed.Findings), len(rep.Findings))
	}
	if len(parsed.Folders) != len(rep.Folders) {
		t.Errorf("Folders: got %d, want %d", len(parsed.Folders), len(rep.Folders))
	}
}
