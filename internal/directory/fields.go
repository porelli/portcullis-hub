package directory

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/portcullis/hub/internal/rules"
)

// LLDAP built-in attributes that can't be used as field names.
var lldapBuiltins = map[string]bool{
	"mail": true, "uid": true, "display_name": true, "first_name": true,
	"last_name": true, "avatar": true, "creation_date": true, "uuid": true, "user_id": true,
}

// fieldNameRe matches valid field names: ^[a-z][a-z0-9_]{0,30}$
var fieldNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,30}$`)

// CreateField creates a custom field.
// admin only (Task 6)
func (s *Service) CreateField(ctx context.Context, actor string, f Field) error {
	f.Name = strings.TrimSpace(f.Name)
	f.Label = strings.TrimSpace(f.Label)
	detail := fmt.Sprintf("kind=%s multi=%v admin_only=%v", f.Kind, f.Multi, f.AdminOnly)
	return s.run(actor, "field.create", f.Name, &detail, func() error {
		if s.Store == nil {
			return &Error{Status: http.StatusServiceUnavailable, Msg: "custom fields not configured"}
		}
		if !fieldNameRe.MatchString(f.Name) {
			return invalid("invalid field name: use lowercase letters, digits, '_', 1-31 characters, starting with a letter")
		}
		if lldapBuiltins[f.Name] {
			return invalid("field name %q is reserved (LLDAP built-in attribute)", f.Name)
		}
		if f.Label == "" {
			return invalid("label is required")
		}
		if utf8.RuneCountInString(f.Label) > 64 {
			return invalid("label must be at most 64 characters")
		}
		if f.Kind != FieldKindText && f.Kind != FieldKindList && f.Kind != FieldKindPerson {
			return invalid("kind must be %q, %q or %q", FieldKindText, FieldKindList, FieldKindPerson)
		}
		if f.Kind == FieldKindPerson && f.Multi {
			return invalid("person fields cannot be multi-valued")
		}
		if f.Kind == FieldKindList {
			trimmed, err := validateListValues(f.Values)
			if err != nil {
				return err
			}
			f.Values = trimmed
		} else {
			// Non-list kinds must have empty Values
			if len(f.Values) > 0 {
				return invalid("%s fields must not have values", f.Kind)
			}
		}

		// Check for duplicates in directory.yaml
		cfg, err := s.Store.Load()
		if err != nil {
			return fmt.Errorf("load directory.yaml: %w", err)
		}
		for _, existing := range cfg.Fields {
			if existing.Name == f.Name {
				return refuse("field %q already exists", f.Name)
			}
		}

		// Check if attribute already exists in LLDAP
		attrs, err := s.LLDAP.UserAttributes(ctx)
		if err != nil {
			return &Error{Status: http.StatusBadGateway, Msg: err.Error()}
		}
		for _, a := range attrs {
			if a.Name == f.Name {
				return refuse("LLDAP attribute %q already exists", f.Name)
			}
		}

		// Create in LLDAP first
		isList := f.Multi
		if err := s.LLDAP.AddUserAttribute(ctx, f.Name, isList); err != nil {
			return &Error{Status: http.StatusBadGateway, Msg: fmt.Sprintf("creating LLDAP attribute: %v", err)}
		}

		// Then save to directory.yaml
		cfg.Fields = append(cfg.Fields, f)
		if err := s.Store.Save(cfg); err != nil {
			// Best-effort rollback: delete the LLDAP attribute
			if derr := s.LLDAP.DeleteUserAttribute(ctx, f.Name); derr != nil {
				return fmt.Errorf("saving directory.yaml failed (%v) and rolling back the LLDAP attribute failed (%v): manually delete attribute %q in LLDAP", err, derr, f.Name)
			}
			return fmt.Errorf("save directory.yaml: %w", err)
		}
		return nil
	})
}

// UpdateField updates a field's mutable properties (Label, Values, ShareWithApps, AdminOnly).
// Kind and Multi are immutable.
// admin only (Task 6)
func (s *Service) UpdateField(ctx context.Context, actor string, f Field) error {
	f.Name = strings.TrimSpace(f.Name)
	f.Label = strings.TrimSpace(f.Label)
	var changes []string
	detail := ""
	return s.run(actor, "field.update", f.Name, &detail, func() error {
		if s.Store == nil {
			return &Error{Status: http.StatusServiceUnavailable, Msg: "custom fields not configured"}
		}
		if f.Label == "" {
			return invalid("label is required")
		}
		if utf8.RuneCountInString(f.Label) > 64 {
			return invalid("label must be at most 64 characters")
		}
		if f.Kind == FieldKindList {
			trimmed, err := validateListValues(f.Values)
			if err != nil {
				return err
			}
			f.Values = trimmed
		} else {
			// Non-list kinds must have empty Values
			if len(f.Values) > 0 {
				return invalid("%s fields must not have values", f.Kind)
			}
		}

		cfg, err := s.Store.Load()
		if err != nil {
			return fmt.Errorf("load directory.yaml: %w", err)
		}

		// Find existing field
		idx := -1
		var existing Field
		for i, field := range cfg.Fields {
			if field.Name == f.Name {
				idx = i
				existing = field
				break
			}
		}
		if idx == -1 {
			return notFound("field %q not found", f.Name)
		}

		// Check Kind and Multi are unchanged
		if existing.Kind != f.Kind {
			return invalid("field kind cannot be changed (was %q)", existing.Kind)
		}
		if existing.Multi != f.Multi {
			return invalid("field multi cannot be changed (was %v)", existing.Multi)
		}

		// Track changes
		if existing.Label != f.Label {
			changes = append(changes, "label")
		}
		if existing.AdminOnly != f.AdminOnly {
			changes = append(changes, fmt.Sprintf("admin_only=%v", f.AdminOnly))
		}
		if existing.ShareWithApps != f.ShareWithApps {
			changes = append(changes, fmt.Sprintf("share_with_apps=%v", f.ShareWithApps))
		}

		// Check if turning off AdminOnly while field is guarded
		if existing.AdminOnly && !f.AdminOnly {
			guarded := s.guardedFields(cfg)
			if group, ok := guarded[f.Name]; ok {
				return refuse("cannot turn off admin-only: field is used by %s (a protected/permission/app-admin group)", group)
			}
		}

		// Check if removing list values that are in use (always compute for list kinds)
		if f.Kind == FieldKindList {
			removed := make(map[string]bool)
			kept := make(map[string]bool)
			for _, v := range f.Values {
				kept[strings.ToLower(v)] = true
			}
			for _, v := range existing.Values {
				if !kept[strings.ToLower(v)] {
					removed[strings.ToLower(v)] = true
				}
			}
			// Track added/removed values
			if len(removed) > 0 || len(kept) > len(existing.Values) {
				var added []string
				existingSet := make(map[string]bool)
				for _, v := range existing.Values {
					existingSet[strings.ToLower(v)] = true
				}
				for _, v := range f.Values {
					if !existingSet[strings.ToLower(v)] {
						added = append(added, v)
					}
				}
				if len(added) > 0 {
					changes = append(changes, fmt.Sprintf("values+%v", added))
				}
				if len(removed) > 0 {
					var removedList []string
					for k := range removed {
						removedList = append(removedList, k)
					}
					sort.Strings(removedList)
					changes = append(changes, fmt.Sprintf("values-%v", removedList))
				}
			}

			// Check if any removed value is used in rules
			if len(removed) > 0 {
				var usingGroups []string
				for groupName, gc := range cfg.Groups {
					if gc.Rule == nil {
						continue
					}
					// Check if rule references this field
					if !containsString(rules.Fields(gc.Rule), f.Name) {
						continue
					}
					// Check if rule uses any removed value
					if usesRemovedValue(gc.Rule, f.Name, removed) {
						usingGroups = append(usingGroups, groupName)
					}
				}
				if len(usingGroups) > 0 {
					sort.Strings(usingGroups)
					return refuse("cannot remove list values: used in rules of %s", strings.Join(usingGroups, ", "))
				}
			}
		}

		// Update
		cfg.Fields[idx] = f
		if err := s.Store.Save(cfg); err != nil {
			return fmt.Errorf("save directory.yaml: %w", err)
		}
		if len(changes) > 0 {
			detail = strings.Join(changes, " ")
		}
		return nil
	})
}

// DeleteField deletes a field. confirm must equal the field name.
// admin only (Task 6)
func (s *Service) DeleteField(ctx context.Context, actor, name, confirm string) error {
	name = strings.TrimSpace(name)
	confirm = strings.TrimSpace(confirm)
	return s.run(actor, "field.delete", name, nil, func() error {
		if s.Store == nil {
			return &Error{Status: http.StatusServiceUnavailable, Msg: "custom fields not configured"}
		}
		if confirm != name {
			return invalid("type the field name to confirm")
		}

		cfg, err := s.Store.Load()
		if err != nil {
			return fmt.Errorf("load directory.yaml: %w", err)
		}

		// Find field
		idx := -1
		for i, field := range cfg.Fields {
			if field.Name == name {
				idx = i
				break
			}
		}
		if idx == -1 {
			return notFound("field %q not found", name)
		}

		// Check if field is used in any rule
		var usingGroups []string
		for groupName, gc := range cfg.Groups {
			if gc.Rule != nil && containsString(rules.Fields(gc.Rule), name) {
				usingGroups = append(usingGroups, groupName)
			}
		}
		if len(usingGroups) > 0 {
			sort.Strings(usingGroups)
			return refuse("field is used in rules of %s", strings.Join(usingGroups, ", "))
		}

		// Delete from directory.yaml first
		cfg.Fields = append(cfg.Fields[:idx], cfg.Fields[idx+1:]...)
		if err := s.Store.Save(cfg); err != nil {
			return fmt.Errorf("save directory.yaml: %w", err)
		}

		// Then delete from LLDAP (deleting the attribute drops all values)
		if err := s.LLDAP.DeleteUserAttribute(ctx, name); err != nil {
			return &Error{Status: http.StatusBadGateway, Msg: fmt.Sprintf("deleting LLDAP attribute failed (%v): the LLDAP attribute %q is left behind and must be removed (portcullis lldap-ui) before re-creating the field", err, name)}
		}

		return nil
	})
}

// guardedFields returns a map of field → group name for fields that are referenced
// by rules of protected groups (admin groups), permission groups, or app admin groups.
// These fields must remain admin-only.
func (s *Service) guardedFields(cfg *Config) map[string]string {
	guarded := make(map[string]string)

	// Collect guarding groups
	guardingGroups := make(map[string]bool)

	// 1. Protected/admin groups
	for name := range s.adminGroups() {
		guardingGroups[name] = true
	}

	// 2. Permission groups
	for _, groupName := range cfg.Permissions {
		guardingGroups[groupName] = true
	}

	// 3. App admin groups
	if s.Apps != nil {
		for _, app := range s.Apps() {
			if app.AdminGroup != "" {
				guardingGroups[app.AdminGroup] = true
			}
		}
	}

	// Find fields used by guarding groups that have rules
	for groupName := range guardingGroups {
		gc, ok := cfg.Groups[groupName]
		if !ok || gc.Rule == nil {
			continue
		}
		for _, field := range rules.Fields(gc.Rule) {
			if _, already := guarded[field]; !already {
				guarded[field] = groupName
			}
		}
	}

	return guarded
}

// validateListValues checks that list values are non-empty, trimmed, and unique (case-insensitive).
// Returns a new slice with trimmed values (does not mutate the input).
func validateListValues(values []string) ([]string, error) {
	seen := make(map[string]string) // lowercase -> original
	result := make([]string, len(values))
	for i, v := range values {
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			return nil, invalid("list values must not be empty or blank")
		}
		lower := strings.ToLower(trimmed)
		if orig, ok := seen[lower]; ok {
			return nil, invalid("duplicate list value: %q and %q (case-insensitive)", orig, trimmed)
		}
		seen[lower] = trimmed
		result[i] = trimmed
	}
	return result, nil
}

// containsString reports whether slice contains s.
func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

// usesRemovedValue checks if a rule uses any of the removed values (case-insensitive).
func usesRemovedValue(e *rules.Expr, fieldName string, removed map[string]bool) bool {
	if e.Field == fieldName {
		for _, v := range e.Values {
			if removed[strings.ToLower(v)] {
				return true
			}
		}
	}
	for _, item := range e.Items {
		if usesRemovedValue(item, fieldName, removed) {
			return true
		}
	}
	return false
}
