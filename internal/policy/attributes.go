package policy

import (
	"encoding/json"
	"strings"
	"unicode"

	"github.com/portcullis/hub/internal/fsutil"
)

// UserAttributesVersion is the user-attributes.json format version
// (contract §4.1).
const UserAttributesVersion = 1

// UserAttributesFile is the file name, next to the policy file.
const UserAttributesFile = "user-attributes.json"

// maxAttrValue: longer values are dropped, not truncated (contract §5).
const maxAttrValue = 1024

// AttrField is a shared custom field (ShareWithApps) for
// BuildUserAttributes.
type AttrField struct {
	Name  string
	Multi bool
}

// UserAttributesDocument is the JSON written for group-gate to populate
// attribute headers (contract §4.1).
type UserAttributesDocument struct {
	Version int                            `json:"version"`
	Fields  map[string]string              `json:"fields"` // field name -> header name
	Users   map[string]map[string][]string `json:"users"`  // username -> field name -> values
}

// BuildUserAttributes constructs the user-attributes.json document from field
// definitions and user data. Only fields in the fields list are included. Users
// are keyed lowercase. Values longer than 1 KB are dropped, and control
// characters are stripped from each value (contract §5).
func BuildUserAttributes(fields []AttrField, users map[string]map[string][]string) UserAttributesDocument {
	doc := UserAttributesDocument{
		Version: UserAttributesVersion,
		Fields:  make(map[string]string, len(fields)),
		Users:   make(map[string]map[string][]string, len(users)),
	}

	// Build fields map with header name derivation
	fieldSet := make(map[string]bool, len(fields))
	for _, f := range fields {
		doc.Fields[f.Name] = fieldToHeader(f.Name)
		fieldSet[f.Name] = true
	}

	// Build users map, filtering and cleaning values
	for user, attrs := range users {
		user = strings.ToLower(user)
		userAttrs := make(map[string][]string)

		for field, values := range attrs {
			// Only include fields that are in the fields list
			if !fieldSet[field] {
				continue
			}

			cleanedVals := make([]string, 0, len(values))
			for _, val := range values {
				// Strip control characters (ASCII 0x00-0x1F and 0x7F)
				cleaned := stripControlChars(val)

				// Drop empty values and values > 1 KB
				if cleaned == "" || len(cleaned) > maxAttrValue {
					continue
				}

				cleanedVals = append(cleanedVals, cleaned)
			}

			if len(cleanedVals) > 0 {
				userAttrs[field] = cleanedVals
			}
		}

		// Only include user if they have at least one attribute
		if len(userAttrs) > 0 {
			doc.Users[user] = userAttrs
		}
	}

	return doc
}

// fieldToHeader converts a field name to its header name: each underscore-
// separated word is capitalized (e.g., "cost_center" → "Cost-Center").
func fieldToHeader(field string) string {
	parts := strings.Split(field, "_")
	for i, part := range parts {
		if len(part) > 0 {
			// Capitalize first letter, lowercase the rest
			runes := []rune(part)
			runes[0] = unicode.ToUpper(runes[0])
			for j := 1; j < len(runes); j++ {
				runes[j] = unicode.ToLower(runes[j])
			}
			parts[i] = string(runes)
		}
	}
	return strings.Join(parts, "-")
}

// stripControlChars removes control characters (ASCII 0x00-0x1F and 0x7F) from s.
func stripControlChars(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7F {
			return -1 // drop the rune
		}
		return r
	}, s)
}

// WriteUserAttributes serializes doc and writes it atomically (temp file +
// rename) with mode 0644, so group-gate can read it.
func WriteUserAttributes(path string, doc UserAttributesDocument) error {
	payload, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(path, append(payload, '\n'), 0644)
}
