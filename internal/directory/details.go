package directory

import (
	"context"
	"fmt"
	"net/http"
	"sort"
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
				return invalid("unknown field: %s", name)
			}

			// AdminOnly check
			if f.AdminOnly && !c.Admin {
				return forbidden("field %s is admin-only", name)
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
					return invalid("field %s: empty values not allowed", name)
				}
				trimmed = append(trimmed, v)
			}

			// Validate by kind
			if !f.Multi && len(trimmed) > 1 {
				return invalid("field %s is single-valued (got %d values)", name, len(trimmed))
			}

			switch f.Kind {
			case FieldKindList:
				// Build allowed set (case-insensitive)
				allowed := make(map[string]bool)
				for _, v := range f.Values {
					allowed[strings.ToLower(v)] = true
				}
				for _, v := range trimmed {
					if !allowed[strings.ToLower(v)] {
						return invalid("field %s: %q is not one of the allowed values", name, v)
					}
				}
			case FieldKindPerson:
				// Must be existing username
				for _, v := range trimmed {
					if _, ok := sn.users[strings.ToLower(v)]; !ok {
						return invalid("field %s: %q is not a known user", name, v)
					}
				}
			case FieldKindText:
				// Check length
				for _, v := range trimmed {
					if utf8.RuneCountInString(v) > maxTextRunes {
						return invalid("field %s: value is too long (max %d characters)", name, maxTextRunes)
					}
				}
			}

			trimmedAttrs[name] = trimmed
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

		return s.LLDAP.SetUserAttributes(ctx, user, set, remove)
	})
}
