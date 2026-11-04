package settings

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
)

// EncodeTSV encodes a data file as TSV (contract §13.7, F6): UTF-8, tab-separated
// fields, `\n` line endings. The first line is version, the second instance, then
// every other line sorted by bytes.
//
// Lists are comma-joined. A field holding a tab, newline, or comma inside a list
// item is an error naming the field.
func EncodeTSV(doc DataFileDoc) ([]byte, error) {
	var buf bytes.Buffer
	var lines []string

	// First line: version
	fmt.Fprintf(&buf, "version\t%d\n", doc.Version)

	// Second line: instance
	if err := checkTSVString(doc.Instance); err != nil {
		return nil, fmt.Errorf("instance: %w", err)
	}
	fmt.Fprintf(&buf, "instance\t%s\n", doc.Instance)

	// Collect all other lines
	// Values
	for key, val := range doc.Values {
		if err := checkTSVString(key); err != nil {
			return nil, fmt.Errorf("value key %q: %w", key, err)
		}
		rendered, err := renderTSVValue(val)
		if err != nil {
			return nil, fmt.Errorf("value %s: %w", key, err)
		}
		lines = append(lines, fmt.Sprintf("value\t%s\t%s", key, rendered))
	}

	// People
	for user, fields := range doc.People {
		if err := checkTSVString(user); err != nil {
			return nil, fmt.Errorf("person %q: %w", user, err)
		}
		for field, val := range fields {
			if err := checkTSVString(field); err != nil {
				return nil, fmt.Errorf("person %s field %q: %w", user, field, err)
			}
			rendered, err := renderTSVValue(val)
			if err != nil {
				return nil, fmt.Errorf("person %s field %s: %w", user, field, err)
			}
			lines = append(lines, fmt.Sprintf("person\t%s\t%s\t%s", user, field, rendered))
		}
	}

	// Groups
	for key, records := range doc.Groups {
		if err := checkTSVString(key); err != nil {
			return nil, fmt.Errorf("group key %q: %w", key, err)
		}
		for _, rec := range records {
			if err := checkTSVString(rec.Group); err != nil {
				return nil, fmt.Errorf("group %s record %q: %w", key, rec.Group, err)
			}
			rendered, err := renderTSVValue(rec.Value)
			if err != nil {
				return nil, fmt.Errorf("group %s record %s: %w", key, rec.Group, err)
			}
			lines = append(lines, fmt.Sprintf("group\t%s\t%s\t%s", key, rec.Group, rendered))
		}
	}

	// Entries
	for field, entries := range doc.Entries {
		if err := checkTSVString(field); err != nil {
			return nil, fmt.Errorf("entry field %q: %w", field, err)
		}
		for _, entry := range entries {
			if err := checkTSVString(entry.User); err != nil {
				return nil, fmt.Errorf("entry %s user %q: %w", field, entry.User, err)
			}
			rendered, err := renderTSVValue(entry.Value)
			if err != nil {
				return nil, fmt.Errorf("entry %s user %s: %w", field, entry.User, err)
			}
			lines = append(lines, fmt.Sprintf("entry\t%s\t%s\t%s", field, entry.User, rendered))
		}
	}

	// Sort the lines
	sort.Strings(lines)

	// Write sorted lines
	for _, line := range lines {
		buf.WriteString(line)
		buf.WriteByte('\n')
	}

	return buf.Bytes(), nil
}

// renderTSVValue renders a value for TSV output. Lists are comma-joined.
// Returns an error if the value contains a tab, newline, or comma (in a list item).
func renderTSVValue(val any) (string, error) {
	switch v := val.(type) {
	case string:
		if err := checkTSVString(v); err != nil {
			return "", err
		}
		return v, nil
	case int, int64, int32, int16, int8:
		return fmt.Sprint(v), nil
	case uint, uint64, uint32, uint16, uint8:
		return fmt.Sprint(v), nil
	case float64, float32:
		return fmt.Sprint(v), nil
	case bool:
		if v {
			return "true", nil
		}
		return "false", nil
	case []any:
		// List: comma-joined
		var items []string
		for _, item := range v {
			rendered, err := renderTSVValue(item)
			if err != nil {
				return "", err
			}
			if strings.Contains(rendered, ",") {
				return "", fmt.Errorf("list item contains comma")
			}
			items = append(items, rendered)
		}
		return strings.Join(items, ","), nil
	default:
		// For other types, try fmt.Sprint
		s := fmt.Sprint(v)
		if err := checkTSVString(s); err != nil {
			return "", err
		}
		return s, nil
	}
}

// checkTSVString checks that s contains no tab or newline.
func checkTSVString(s string) error {
	if strings.ContainsAny(s, "\t\n\r") {
		return fmt.Errorf("value contains tab or newline")
	}
	return nil
}
