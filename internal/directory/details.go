package directory

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// SetDetails sets custom field values for a user. Delegates need edit_details
// and go through checkDelegateTarget. AdminOnly fields are admins only.
// An empty value list removes the attribute. Unknown fields are refused.
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

		// Build field map
		fields := make(map[string]Field)
		for _, f := range cfg.Fields {
			fields[f.Name] = f
		}

		// Validate all attrs first
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
				continue
			}

			// Validate by kind
			if !f.Multi && len(vals) > 1 {
				return invalid("field %s is single-valued (got %d values)", name, len(vals))
			}

			switch f.Kind {
			case FieldKindList:
				// Build allowed set (case-insensitive)
				allowed := make(map[string]bool)
				for _, v := range f.Values {
					allowed[strings.ToLower(v)] = true
				}
				for _, v := range vals {
					if !allowed[strings.ToLower(v)] {
						return invalid("field %s: %q is not one of the allowed values", name, v)
					}
				}
			case FieldKindPerson:
				// Must be existing username
				sn, err := s.load(ctx)
				if err != nil {
					return err
				}
				for _, v := range vals {
					if _, ok := sn.users[strings.ToLower(v)]; !ok {
						return invalid("field %s: %q is not a known user", name, v)
					}
				}
			}
		}

		// Check target (protected accounts)
		if err := s.checkTarget(user); err != nil {
			return err
		}

		// Now apply the changes to LLDAP
		set := make(map[string][]string)
		var remove []string

		for name, vals := range attrs {
			if len(vals) == 0 {
				remove = append(remove, name)
			} else {
				set[name] = vals
			}
		}

		return s.LLDAP.SetUserAttributes(ctx, user, set, remove)
	})
}
