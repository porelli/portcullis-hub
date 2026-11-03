package policy

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/portcullis/hub/internal/fsutil"
)

// UserAttributesVersion is the user-attributes.json format version
// (contract §4.1): the Hub writes only version 2 (fields, users and the
// per-host header-delivery headers); group-gate refuses any other.
const UserAttributesVersion = 2

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
	// Hosts: host → header suffix (the part after X-Forwarded-Attr-,
	// e.g. "Grafana-Role") → username → value (header deliveries,
	// contract §13.6). Always an object.
	Hosts map[string]map[string]map[string]string `json:"hosts"`
}

// HeaderPrefix starts every attribute header; hosts keys are what
// follows it.
const HeaderPrefix = "X-Forwarded-Attr-"

// HeaderNameRe is the one header-delivery name form (contract §13.6):
// HeaderPrefix + group-gate's header suffix form (_ATTR_HEADER_RE). The
// templates validator uses it (templates.HeaderDeliveryRe), so every
// accepted name survives BuildHosts and group-gate.
var HeaderNameRe = regexp.MustCompile(`^X-Forwarded-Attr-[A-Za-z0-9]+(-[A-Za-z0-9]+){0,30}$`)

// BuildUserAttributes constructs the user-attributes.json document from field
// definitions and user data. Only fields in the fields list are included. Users
// are keyed lowercase. Values longer than 1 KB are dropped, and control
// characters are stripped from each value (contract §5). hosts is the
// per-host section (BuildHosts).
func BuildUserAttributes(fields []AttrField, users map[string]map[string][]string, hosts map[string]map[string]map[string]string) UserAttributesDocument {
	doc := UserAttributesDocument{
		Version: UserAttributesVersion,
		Fields:  make(map[string]string, len(fields)),
		Users:   make(map[string]map[string][]string, len(users)),
		Hosts:   BuildHosts(hosts),
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

// SuppressFieldHeaders drops every shared field whose header (the part
// after HeaderPrefix, folded) is in suffixes, with its users' values:
// a header delivery whose gated hosts are unknown could not declare it
// per host, so the field header goes nowhere (fail closed).
func SuppressFieldHeaders(doc *UserAttributesDocument, suffixes map[string]bool) {
	if doc == nil || len(suffixes) == 0 {
		return
	}
	// New maps: doc may share them with the directory's document.
	fields := make(map[string]string, len(doc.Fields))
	for name, hdr := range doc.Fields {
		if !suffixes[strings.ToLower(hdr)] {
			fields[name] = hdr
		}
	}
	users := make(map[string]map[string][]string, len(doc.Users))
	for user, vals := range doc.Users {
		kept := make(map[string][]string, len(vals))
		for name, v := range vals {
			if _, ok := fields[name]; ok {
				kept[name] = v
			}
		}
		if len(kept) > 0 {
			users[user] = kept
		}
	}
	doc.Fields, doc.Users = fields, users
}

// BuildHosts cleans the hosts section (host → header suffix → user →
// value; never nil) so group-gate accepts the file: hosts and users
// lowercase (two spellings of one: the first in sorted order); header
// suffixes in group-gate's form and not starting with X-Forwarded-Attr-
// (others dropped; of two differing only in case, the first in sorted
// order — group-gate would refuse the whole file); values control-
// stripped, empty or over 1 KB dropped. A declared header keeps its key
// without values (on that host it replaces a same-named field header);
// a host without headers is left out.
func BuildHosts(hosts map[string]map[string]map[string]string) map[string]map[string]map[string]string {
	out := make(map[string]map[string]map[string]string, len(hosts))
	for _, host := range sortedKeys(hosts) {
		key := strings.ToLower(strings.TrimSpace(host))
		if _, dup := out[key]; dup || key == "" {
			continue
		}
		headers := map[string]map[string]string{}
		seen := map[string]bool{}
		for _, hdr := range sortedKeys(hosts[host]) {
			folded := strings.ToLower(hdr)
			if !HeaderNameRe.MatchString(HeaderPrefix+hdr) || strings.HasPrefix(folded, strings.ToLower(HeaderPrefix)) || seen[folded] {
				continue
			}
			seen[folded] = true
			byUser := hosts[host][hdr]
			vals := make(map[string]string, len(byUser))
			for _, user := range sortedKeys(byUser) {
				u := strings.ToLower(strings.TrimSpace(user))
				if _, dup := vals[u]; dup || u == "" {
					continue
				}
				v := stripControlChars(byUser[user])
				if v == "" || len(v) > maxAttrValue {
					continue
				}
				vals[u] = v
			}
			headers[hdr] = vals
		}
		if len(headers) > 0 {
			out[key] = headers
		}
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
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
