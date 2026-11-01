package directory

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const maxTextRunes = 1024

// SetDetails sets custom field values for a user. Delegates need edit_details
// and go through checkDelegateTarget. AdminOnly fields are admins only.
// An empty value list removes the attribute. Unknown fields are refused.
// Values are trimmed; empty strings are refused. Text values > 1024 runes are refused.
func (s *Service) SetDetails(ctx context.Context, c *Caller, user string, attrs map[string][]string) error {
	user = strings.TrimSpace(user)
	changes := []string{}
	for k := range attrs {
		changes = append(changes, k)
	}
	sort.Strings(changes)
	detail := fmt.Sprintf("fields=%s", strings.Join(changes, ","))

	return s.run(ctx, c, PermEditDetails, "user.details", user, &detail, func() error {
		if s.Store == nil {
			return &Error{Status: http.StatusServiceUnavailable, Msg: "custom fields not configured"}
		}

		cfg, err := s.Store.Load()
		if err != nil {
			return &Error{Status: http.StatusServiceUnavailable, Msg: "directory.yaml: " + err.Error()}
		}

		// Load snapshot once
		sn, err := s.load(ctx)
		if err != nil {
			return err
		}

		trimmedAttrs, err := checkDetails(c, cfg, sn, attrs)
		if err != nil {
			return err
		}

		// Check target (protected accounts)
		if err := s.checkTarget(user); err != nil {
			return err
		}

		// Now apply the changes to LLDAP
		set := make(map[string][]string)
		var remove []string

		for name, vals := range trimmedAttrs {
			if len(vals) == 0 {
				remove = append(remove, name)
			} else {
				set[name] = vals
			}
		}
		if u, ok := sn.users[strings.ToLower(user)]; ok {
			detail += changeDetail(u.Attributes, trimmedAttrs)
		}

		return s.LLDAP.SetUserAttributes(ctx, user, set, remove)
	})
}

// checkDetails validates attrs as SetDetails does (known fields, admin-only
// fields for admins only, values trimmed and non-empty, single-valued,
// list values canonicalised, person values existing users, text length)
// and returns them trimmed; an empty list means "remove". Caller holds
// s.mu.
func checkDetails(c *Caller, cfg *Config, sn *snapshot, attrs map[string][]string) (map[string][]string, error) {
	// Build field map
	fields := make(map[string]Field)
	for _, f := range cfg.Fields {
		fields[f.Name] = f
	}

	// Trim and validate all attrs first
	trimmedAttrs := make(map[string][]string)
	for name, vals := range attrs {
		f, ok := fields[name]
		if !ok {
			return nil, invalid("unknown field: %s", name)
		}

		// AdminOnly check
		if f.AdminOnly && !c.Admin {
			return nil, forbidden("field %s is admin-only", name)
		}

		// Empty value list = remove (allowed)
		if len(vals) == 0 {
			trimmedAttrs[name] = []string{}
			continue
		}

		// Trim values and refuse empty strings
		trimmed := make([]string, 0, len(vals))
		for _, v := range vals {
			v = strings.TrimSpace(v)
			if v == "" {
				return nil, invalid("field %s: empty values not allowed", name)
			}
			trimmed = append(trimmed, v)
		}

		// Validate by kind
		if !f.Multi && len(trimmed) > 1 {
			return nil, invalid("field %s is single-valued (got %d values)", name, len(trimmed))
		}

		switch f.Kind {
		case FieldKindList:
			// Matched case-insensitively, stored as the defined value:
			// rules compare case-insensitively anyway, but apps
			// (attr_* claims, X-Forwarded-Attr-* headers) compare
			// exactly and must see the defined spelling.
			canon := make(map[string]string)
			for _, v := range f.Values {
				canon[strings.ToLower(v)] = v
			}
			for i, v := range trimmed {
				c, ok := canon[strings.ToLower(v)]
				if !ok {
					return nil, invalid("field %s: %q is not one of the allowed values", name, v)
				}
				trimmed[i] = c
			}
		case FieldKindPerson:
			// Must be existing username
			for _, v := range trimmed {
				if _, ok := sn.users[strings.ToLower(v)]; !ok {
					return nil, invalid("field %s: %q is not a known user", name, v)
				}
			}
		case FieldKindText:
			// Check length
			for _, v := range trimmed {
				if utf8.RuneCountInString(v) > maxTextRunes {
					return nil, invalid("field %s: value is too long (max %d characters)", name, maxTextRunes)
				}
			}
		}

		trimmedAttrs[name] = trimmed
	}
	return trimmedAttrs, nil
}

// maxAuditValue bounds one field value in the audit detail (bytes).
const maxAuditValue = 64

// changeDetail is " field=old→new" for every field in set whose values
// differ from old (sorted by field; values clipped; "" = none, several
// values joined with '|').
func changeDetail(old, set map[string][]string) string {
	names := make([]string, 0, len(set))
	for n := range set {
		names = append(names, n)
	}
	sort.Strings(names)
	fmtVals := func(vs []string) string {
		out := make([]string, len(vs))
		for i, v := range vs {
			out[i] = clipN(v, maxAuditValue)
		}
		return strconv.Quote(strings.Join(out, "|"))
	}
	var b strings.Builder
	for _, n := range names {
		before, after := old[n], set[n]
		if slices.Equal(before, after) {
			continue
		}
		fmt.Fprintf(&b, " %s=%s→%s", n, fmtVals(before), fmtVals(after))
	}
	return b.String()
}
