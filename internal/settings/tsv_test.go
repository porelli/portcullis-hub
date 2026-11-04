package settings

import (
	"bytes"
	"strings"
	"testing"
)

// TestEncodeTSV checks the TSV encoder (F6).
func TestEncodeTSV(t *testing.T) {
	t.Run("people doc", func(t *testing.T) {
		doc := DataFileDoc{
			Version:  1,
			Instance: "test-instance",
			Values:   map[string]any{"share_prefix": "/shares"},
			People: map[string]map[string]any{
				"alice": {"uid": int64(20000), "groups": "readers,writers"},
				"bob":   {"uid": int64(20001)},
			},
			Groups: map[string][]GroupRecordOut{
				"acl": {
					{Group: "admins", Value: "write"},
					{Group: "users", Value: "read"},
				},
			},
			Entries: map[string][]EntryOut{
				"note": {
					{User: "alice", Value: "my note"},
				},
			},
		}

		out, err := EncodeTSV(doc)
		if err != nil {
			t.Fatalf("EncodeTSV: %v", err)
		}

		lines := strings.Split(string(out), "\n")
		if len(lines) < 2 {
			t.Fatalf("EncodeTSV: got %d lines, want at least 2", len(lines))
		}

		// First line: version
		if lines[0] != "version\t1" {
			t.Errorf("line 0: got %q, want %q", lines[0], "version\t1")
		}

		// Second line: instance
		if lines[1] != "instance\ttest-instance" {
			t.Errorf("line 1: got %q, want %q", lines[1], "instance\ttest-instance")
		}

		// Rest should be sorted
		rest := lines[2:]
		if len(rest) > 0 && rest[len(rest)-1] == "" {
			rest = rest[:len(rest)-1] // trim trailing empty line
		}

		// Check sorting
		for i := 1; i < len(rest); i++ {
			if rest[i] < rest[i-1] {
				t.Errorf("lines not sorted: %q comes before %q", rest[i-1], rest[i])
			}
		}

		// Check for expected content
		content := string(out)
		if !strings.Contains(content, "value\tshare_prefix\t/shares") {
			t.Error("missing value line for share_prefix")
		}
		if !strings.Contains(content, "person\talice\tuid\t20000") {
			t.Error("missing person line for alice uid")
		}
		if !strings.Contains(content, "person\talice\tgroups\treaders,writers") {
			t.Error("missing person line for alice groups")
		}
		if !strings.Contains(content, "person\tbob\tuid\t20001") {
			t.Error("missing person line for bob uid")
		}
		if !strings.Contains(content, "group\tacl\tadmins\twrite") {
			t.Error("missing group line for acl/admins")
		}
		if !strings.Contains(content, "group\tacl\tusers\tread") {
			t.Error("missing group line for acl/users")
		}
		if !strings.Contains(content, "entry\tnote\talice\tmy note") {
			t.Error("missing entry line for alice note")
		}
	})

	t.Run("value with tab", func(t *testing.T) {
		doc := DataFileDoc{
			Version:  1,
			Instance: "test",
			Values:   map[string]any{"bad": "has\ttab"},
			People:   map[string]map[string]any{},
			Groups:   map[string][]GroupRecordOut{},
			Entries:  map[string][]EntryOut{},
		}

		_, err := EncodeTSV(doc)
		if err == nil {
			t.Error("EncodeTSV: want error for tab in value, got nil")
		}
		if err != nil && !strings.Contains(err.Error(), "bad") {
			t.Errorf("EncodeTSV: want error mentioning field 'bad', got %v", err)
		}
	})

	t.Run("value with newline", func(t *testing.T) {
		doc := DataFileDoc{
			Version:  1,
			Instance: "test",
			Values:   map[string]any{"bad": "has\nnewline"},
			People:   map[string]map[string]any{},
			Groups:   map[string][]GroupRecordOut{},
			Entries:  map[string][]EntryOut{},
		}

		_, err := EncodeTSV(doc)
		if err == nil {
			t.Error("EncodeTSV: want error for newline in value, got nil")
		}
	})

	t.Run("list with comma in item", func(t *testing.T) {
		doc := DataFileDoc{
			Version:  1,
			Instance: "test",
			Values:   map[string]any{"items": []any{"one", "two,three"}},
			People:   map[string]map[string]any{},
			Groups:   map[string][]GroupRecordOut{},
			Entries:  map[string][]EntryOut{},
		}

		_, err := EncodeTSV(doc)
		if err == nil {
			t.Error("EncodeTSV: want error for comma in list item, got nil")
		}
	})

	t.Run("empty document", func(t *testing.T) {
		doc := NewDataFileDoc("empty-instance")

		out, err := EncodeTSV(doc)
		if err != nil {
			t.Fatalf("EncodeTSV: %v", err)
		}

		lines := strings.Split(string(out), "\n")
		if len(lines) < 2 {
			t.Fatalf("EncodeTSV: got %d lines, want at least 2", len(lines))
		}
		if lines[0] != "version\t1" {
			t.Errorf("line 0: got %q, want %q", lines[0], "version\t1")
		}
		if lines[1] != "instance\tempty-instance" {
			t.Errorf("line 1: got %q, want %q", lines[1], "instance\tempty-instance")
		}
	})

	t.Run("empty string value", func(t *testing.T) {
		doc := DataFileDoc{
			Version:  1,
			Instance: "test",
			Values:   map[string]any{"empty": ""},
			People:   map[string]map[string]any{},
			Groups:   map[string][]GroupRecordOut{},
			Entries:  map[string][]EntryOut{},
		}

		out, err := EncodeTSV(doc)
		if err != nil {
			t.Fatalf("EncodeTSV: %v", err)
		}

		// Should have value line with empty last field
		if !strings.Contains(string(out), "value\tempty\t\n") {
			t.Error("missing value line with empty field")
		}
	})
}

// TestEncodeTSVSorting checks that lines are sorted by bytes.
func TestEncodeTSVSorting(t *testing.T) {
	doc := DataFileDoc{
		Version:  1,
		Instance: "test",
		Values: map[string]any{
			"zebra":  "z",
			"apple":  "a",
			"banana": "b",
		},
		People: map[string]map[string]any{
			"zara":  {"uid": int64(20002)},
			"alice": {"uid": int64(20000)},
			"bob":   {"uid": int64(20001)},
		},
		Groups:  map[string][]GroupRecordOut{},
		Entries: map[string][]EntryOut{},
	}

	out, err := EncodeTSV(doc)
	if err != nil {
		t.Fatalf("EncodeTSV: %v", err)
	}

	lines := strings.Split(string(out), "\n")
	// Skip version and instance
	dataLines := lines[2:]
	if len(dataLines) > 0 && dataLines[len(dataLines)-1] == "" {
		dataLines = dataLines[:len(dataLines)-1]
	}

	// Verify sorting
	for i := 1; i < len(dataLines); i++ {
		if bytes.Compare([]byte(dataLines[i]), []byte(dataLines[i-1])) < 0 {
			t.Errorf("line %d not sorted: %q should come before %q", i+2, dataLines[i], dataLines[i-1])
		}
	}
}
