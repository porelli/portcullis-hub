package directory

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/portcullis/hub/internal/invite"
	"github.com/portcullis/hub/internal/lldap"
)

const (
	maxCSVRows    = 10000
	maxCSVColumns = 64
	maxCSVBytes   = 5 * 1024 * 1024 // 5 MB
)

// ParseCSV parses a CSV file and returns the header and rows.
// It detects the separator (comma or semicolon) from the header line (counting outside quotes),
// handles BOM, CRLF, and quoted newlines.
// Refuses files > 10,000 rows or > 64 columns.
func ParseCSV(r io.Reader) (header []string, rows [][]string, err error) {
	// Read all data (limited by HTTP layer, but also check here)
	data, err := io.ReadAll(io.LimitReader(r, maxCSVBytes+1))
	if err != nil {
		return nil, nil, invalid("read CSV: %v", err)
	}
	if len(data) > maxCSVBytes {
		return nil, nil, invalid("CSV file too large (max 5 MB)")
	}

	// Strip BOM if present
	data = bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})

	// Detect separator from first line, counting only outside quotes
	separator := ','
	firstLine := data
	if idx := bytes.IndexByte(data, '\n'); idx >= 0 {
		firstLine = data[:idx]
	}
	commas, semicolons := 0, 0
	inQuote := false
	for _, b := range firstLine {
		if b == '"' {
			inQuote = !inQuote
		} else if !inQuote {
			if b == ',' {
				commas++
			} else if b == ';' {
				semicolons++
			}
		}
	}
	if semicolons > commas {
		separator = ';'
	}

	// Parse CSV
	reader := csv.NewReader(bytes.NewReader(data))
	reader.Comma = separator
	reader.TrimLeadingSpace = true
	reader.FieldsPerRecord = -1 // allow ragged rows

	records, err := reader.ReadAll()
	if err != nil {
		return nil, nil, invalid("parse CSV: %v", err)
	}

	if len(records) == 0 {
		return nil, nil, invalid("CSV file is empty")
	}
	return NormalizeImport(records[0], records[1:])
}

// NormalizeImport checks an import's size (at most 10,000 rows and 64
// columns), lowercases and trims the header and requires a unique
// "username" column. ParseCSV ends with it; the API calls it for rows the
// UI sends back for a fresh review.
func NormalizeImport(head []string, rows [][]string) (header []string, out [][]string, err error) {
	if len(rows) > maxCSVRows {
		return nil, nil, invalid("CSV file has too many rows (max %d)", maxCSVRows)
	}
	if len(head) > maxCSVColumns {
		return nil, nil, invalid("CSV file has too many columns (max %d)", maxCSVColumns)
	}
	for _, r := range rows {
		if len(r) > maxCSVColumns {
			return nil, nil, invalid("CSV row has too many columns (max %d)", maxCSVColumns)
		}
	}

	// Normalize header (lowercase, trim)
	header = make([]string, len(head))
	seen := make(map[string]bool)
	for i, h := range head {
		h = strings.TrimSpace(h)
		h = strings.ToLower(h)
		header[i] = h
		if h != "" && seen[h] {
			return nil, nil, invalid("duplicate column header: %q", h)
		}
		seen[h] = true
	}
	if !seen["username"] {
		return nil, nil, invalid("CSV must have a %q column", "username")
	}
	if rows == nil {
		rows = [][]string{}
	}
	return header, rows, nil
}

// Cell represents a field cell in the import review.
type Cell struct {
	Current []string `json:"current"` // current values in LLDAP
	File    []string `json:"file"`    // values from the CSV file
}

// ReviewRow is one row in the import review.
type ReviewRow struct {
	User     string          `json:"user"`
	Status   string          `json:"status"` // new|changed|missing|same
	Cells    map[string]Cell `json:"cells"`  // field name -> cell
	Problems []string        `json:"problems"`
}

// Review is the result of ImportReview.
type Review struct {
	Rows           []ReviewRow       `json:"rows"`
	UnknownColumns []string          `json:"unknown_columns"`
	Effect         map[string][2]int `json:"effect"` // group -> [added, removed]
}

// ImportReview reads the CSV data and returns a review of the changes.
// It requires edit_details OR invite OR remove permission.
// Rows are marked with problems that the caller couldn't apply.
// Missing rows are unticked by default (ticking a Remove row is the confirmation).
func (s *Service) ImportReview(ctx context.Context, c *Caller, header []string, rows [][]string) (*Review, error) {
	// Authorization: edit_details OR invite OR remove (any)
	hasAnyPerm := c.Admin || c.Perms[PermEditDetails] || c.Perms[PermInvite] || c.Perms[PermRemove]
	if !hasAnyPerm {
		return nil, forbidden("not allowed: needs %s, %s or %s", PermEditDetails, PermInvite, PermRemove)
	}

	review := &Review{
		Rows:           []ReviewRow{},
		UnknownColumns: []string{},
		Effect:         make(map[string][2]int),
	}

	// Get snapshot (not holding s.mu across this)
	sn, err := s.load(ctx)
	if err != nil {
		return nil, err
	}

	// Get config for fields
	var cfg *Config
	var fields map[string]Field
	if s.Store != nil {
		cfg, err = s.Store.Load()
		if err != nil {
			return nil, &Error{Status: http.StatusServiceUnavailable, Msg: "directory.yaml: " + err.Error()}
		}
		fields = make(map[string]Field)
		for _, f := range cfg.Fields {
			fields[f.Name] = f
		}
	} else {
		cfg = &Config{
			Version:     1,
			Fields:      []Field{},
			Groups:      map[string]*GroupConfig{},
			Permissions: map[string]string{},
			CreatedBy:   map[string]string{},
			Deleted:     map[string]time.Time{},
		}
		fields = make(map[string]Field)
	}

	// Check for required username column early (before processing rows)
	usernameCol := -1
	for i, h := range header {
		if h == "username" {
			usernameCol = i
			break
		}
	}
	if usernameCol < 0 {
		return nil, invalid("CSV must have a %q column", "username")
	}

	// Build column map
	colMap := make(map[string]int) // field name -> column index
	displayNameCol := -1
	emailCol := -1

	for i, h := range header {
		switch h {
		case "username":
			// Already found above
		case "display_name":
			displayNameCol = i
		case "email":
			emailCol = i
		default:
			if _, ok := fields[h]; ok {
				colMap[h] = i
			} else if h != "" {
				review.UnknownColumns = append(review.UnknownColumns, h)
			}
		}
	}
	sort.Strings(review.UnknownColumns)

	// Track usernames in the file (case-insensitive) to detect duplicates
	fileUsers := make(map[string][]string) // lowercase -> original usernames
	for _, row := range rows {
		if usernameCol < len(row) {
			user := strings.TrimSpace(row[usernameCol])
			if user != "" {
				lower := strings.ToLower(user)
				fileUsers[lower] = append(fileUsers[lower], user)
			}
		}
	}

	// Process each row in the file
	for _, row := range rows {
		if usernameCol < len(row) {
			user := strings.TrimSpace(row[usernameCol])
			if user == "" {
				// Empty username row: add problem
				rr := ReviewRow{
					User:     "(empty)",
					Status:   "new",
					Cells:    make(map[string]Cell),
					Problems: []string{"username is required"},
				}
				review.Rows = append(review.Rows, rr)
				continue
			}
			rr := s.reviewRow(ctx, c, user, row, header, colMap, displayNameCol, emailCol, sn, cfg, fields, fileUsers)
			review.Rows = append(review.Rows, rr)
		} else {
			// Short row (no username cell)
			rr := ReviewRow{
				User:     "(missing)",
				Status:   "new",
				Cells:    make(map[string]Cell),
				Problems: []string{"row is too short (no username column)"},
			}
			review.Rows = append(review.Rows, rr)
		}
	}

	// Add "missing" rows: users in LLDAP but not in the file
	missingUsers := []string{}
	for user := range sn.users {
		lower := strings.ToLower(user)
		if _, inFile := fileUsers[lower]; !inFile {
			// Skip protected accounts
			if s.checkTarget(user) != nil {
				continue
			}
			missingUsers = append(missingUsers, user)
		}
	}
	sort.Strings(missingUsers)
	for _, user := range missingUsers {
		lower := strings.ToLower(user)
		rr := ReviewRow{
			User:     user,
			Status:   "missing",
			Cells:    make(map[string]Cell),
			Problems: []string{},
		}
		// Fill current values
		u := sn.users[lower]
		for fname := range fields {
			if vals, ok := u.Attributes[fname]; ok {
				rr.Cells[fname] = Cell{Current: vals, File: nil}
			}
		}
		// Check remove permission and delegate target
		if !c.Admin && !c.Perms[PermRemove] {
			rr.Problems = append(rr.Problems, "removing users requires the remove permission")
		}
		if !c.Admin {
			if err := s.checkDelegateTarget(c, user, sn, cfg); err != nil {
				rr.Problems = append(rr.Problems, fmt.Sprintf("only an admin can change %s", user))
			}
		}
		review.Rows = append(review.Rows, rr)
	}

	// Compute Effect on rule groups (exclude missing rows by default)
	review.Effect = s.computeEffect(ctx, cfg, sn, review.Rows, time.Now(), false)

	return review, nil
}

func (s *Service) reviewRow(ctx context.Context, c *Caller, user string, row []string, header []string, colMap map[string]int, displayNameCol, emailCol int, sn *snapshot, cfg *Config, fields map[string]Field, fileUsers map[string][]string) ReviewRow {
	rr := ReviewRow{
		User:     user,
		Status:   "new",
		Cells:    make(map[string]Cell),
		Problems: []string{},
	}

	lower := strings.ToLower(user)

	// Check for short rows (fewer cells than header)
	if len(row) < len(header) {
		rr.Problems = append(rr.Problems, fmt.Sprintf("row has %d cells, header has %d", len(row), len(header)))
		// Short rows are flagged; Apply will refuse them
	}

	// Check for duplicate usernames in file
	if len(fileUsers[lower]) > 1 {
		rr.Problems = append(rr.Problems, fmt.Sprintf("duplicate username in file: %s", strings.Join(fileUsers[lower], ", ")))
	}

	u, exists := sn.users[lower]
	if exists {
		rr.Status = "same" // will be changed to "changed" if differences found
	}

	// Determine what changes this row would make
	nameChanged := false
	emailChanged := false
	attrsChanged := false

	// Check display_name
	var fileDisplayName string
	displayNamePresent := displayNameCol >= 0 && displayNameCol < len(row)
	if displayNamePresent {
		fileDisplayName = strings.TrimSpace(row[displayNameCol])
		if exists {
			if fileDisplayName == "" {
				// Existing user: cannot clear display_name
				rr.Problems = append(rr.Problems, "cannot clear display_name by import")
			} else if u.DisplayName != fileDisplayName {
				nameChanged = true
			}
		}
	}

	// Check email
	var fileEmail string
	emailPresent := emailCol >= 0 && emailCol < len(row)
	if emailPresent {
		fileEmail = strings.TrimSpace(row[emailCol])
		if exists {
			if fileEmail == "" {
				// Existing user: cannot clear email
				rr.Problems = append(rr.Problems, "cannot clear email by import")
			} else if u.Email != fileEmail {
				emailChanged = true
			}
		}
	}

	// Process custom fields
	for fname, col := range colMap {
		f := fields[fname]

		// If column is beyond row length, treat as ABSENT (untouched)
		if col >= len(row) {
			// Don't add to Cells - column is absent
			continue
		}

		var fileVals []string
		cellValue := strings.TrimSpace(row[col])
		if cellValue != "" {
			// Multi-valued cells use |
			if f.Multi || strings.Contains(cellValue, "|") {
				parts := strings.Split(cellValue, "|")
				for _, p := range parts {
					p = strings.TrimSpace(p)
					if p != "" {
						fileVals = append(fileVals, p)
					}
				}
			} else {
				fileVals = []string{cellValue}
			}
		}
		// else: empty cell means clear (file value is empty slice)

		var currentVals []string
		if exists && u.Attributes != nil {
			if vals, ok := u.Attributes[fname]; ok {
				currentVals = vals
			}
		}

		// Build cell (column is present, even if empty)
		rr.Cells[fname] = Cell{Current: currentVals, File: fileVals}

		// Check if changed
		if !stringSliceEqual(currentVals, fileVals) {
			attrsChanged = true
		}

		// Validate file values
		problems := s.validateFieldValues(f, fileVals, sn)
		for _, p := range problems {
			rr.Problems = append(rr.Problems, fmt.Sprintf("field %s: %s", fname, p))
		}

		// Check permission for AdminOnly fields if changed or emptied
		if f.AdminOnly && !c.Admin && !stringSliceEqual(currentVals, fileVals) {
			if len(fileVals) == 0 {
				rr.Problems = append(rr.Problems, fmt.Sprintf("field %s is admin-only (cannot be emptied by a delegate)", fname))
			} else {
				rr.Problems = append(rr.Problems, fmt.Sprintf("field %s is admin-only", fname))
			}
		}
	}

	changed := nameChanged || emailChanged || attrsChanged

	if exists {
		if changed {
			rr.Status = "changed"
		}

		// For changed rows, check permissions based on what changed
		if changed && rr.Status != "same" {
			// Display name or email change requires edit_details
			if (nameChanged || emailChanged) && !c.Admin && !c.Perms[PermEditDetails] {
				rr.Problems = append(rr.Problems, "changing display_name or email requires the edit_details permission")
			}

			// Attribute changes require edit_details
			if attrsChanged && !c.Admin && !c.Perms[PermEditDetails] {
				rr.Problems = append(rr.Problems, "changing custom fields requires the edit_details permission")
			}

			// Delegate target check for changed rows
			if !c.Admin {
				if err := s.checkDelegateTarget(c, user, sn, cfg); err != nil {
					rr.Problems = append(rr.Problems, fmt.Sprintf("only an admin can change %s", user))
				}
			}
		}
	} else {
		// New user validation
		rr.Status = "new"

		// Check invite permission
		if !c.Admin && !c.Perms[PermInvite] {
			rr.Problems = append(rr.Problems, "creating new users requires the invite permission")
		}

		// If new user has attrs, also needs edit_details
		if attrsChanged && !c.Admin && !c.Perms[PermEditDetails] {
			rr.Problems = append(rr.Problems, "creating users with custom fields requires both invite and edit_details permissions")
		}

		// Check for tombstone (delegates)
		if !c.Admin {
			if _, deleted := cfg.Deleted[lower]; deleted {
				rr.Problems = append(rr.Problems, fmt.Sprintf("%s was deleted; an admin must re-create it", user))
			}
		}

		// Basic validation
		if displayNameCol >= 0 && displayNameCol < len(row) {
			displayName := strings.TrimSpace(row[displayNameCol])
			if displayName == "" {
				rr.Problems = append(rr.Problems, "display_name is required for new users")
			} else if utf8.RuneCountInString(displayName) > 128 {
				rr.Problems = append(rr.Problems, "display_name must be at most 128 characters")
			}
		} else {
			rr.Problems = append(rr.Problems, "display_name is required for new users")
		}

		if emailCol >= 0 && emailCol < len(row) {
			email := strings.TrimSpace(row[emailCol])
			if email == "" {
				rr.Problems = append(rr.Problems, "email is required for new users")
			} else if !strings.Contains(email, "@") {
				rr.Problems = append(rr.Problems, "email must be a valid email address")
			}
		} else {
			rr.Problems = append(rr.Problems, "email is required for new users")
		}
	}

	return rr
}

func (s *Service) validateFieldValues(f Field, vals []string, sn *snapshot) []string {
	var problems []string

	if len(vals) == 0 {
		return nil
	}

	// Check multi-valued constraint
	if !f.Multi && len(vals) > 1 {
		problems = append(problems, fmt.Sprintf("field is single-valued (got %d values)", len(vals)))
	}

	switch f.Kind {
	case FieldKindList:
		allowed := make(map[string]bool)
		for _, v := range f.Values {
			allowed[strings.ToLower(v)] = true
		}
		for _, v := range vals {
			if !allowed[strings.ToLower(v)] {
				problems = append(problems, fmt.Sprintf("%q is not one of the allowed values", v))
			}
		}
	case FieldKindPerson:
		for _, v := range vals {
			if _, ok := sn.users[strings.ToLower(v)]; !ok {
				problems = append(problems, fmt.Sprintf("%q is not a known user", v))
			}
		}
	case FieldKindText:
		for _, v := range vals {
			if utf8.RuneCountInString(v) > maxTextRunes {
				problems = append(problems, fmt.Sprintf("%q is too long (max %d characters)", v, maxTextRunes))
			}
		}
	}

	return problems
}

func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	// Copy and sort for comparison
	aCopy := make([]string, len(a))
	bCopy := make([]string, len(b))
	copy(aCopy, a)
	copy(bCopy, b)
	sort.Strings(aCopy)
	sort.Strings(bCopy)
	for i := range aCopy {
		if aCopy[i] != bCopy[i] {
			return false
		}
	}
	return true
}

func (s *Service) computeEffect(ctx context.Context, cfg *Config, sn *snapshot, rows []ReviewRow, now time.Time, includeRemovals bool) map[string][2]int {
	// Build a hypothetical snapshot with the changes applied
	hypothetical := s.applyChangesToSnapshot(sn, rows, cfg, includeRemovals)

	// Compute desired membership before and after
	before := s.Desired(cfg, sn, now)
	after := s.Desired(cfg, hypothetical, now)

	// Calculate differences
	effect := make(map[string][2]int)
	allGroups := make(map[string]bool)
	for g := range before {
		allGroups[g] = true
	}
	for g := range after {
		allGroups[g] = true
	}

	for g := range allGroups {
		added := 0
		removed := 0

		beforeMembers := before[g]
		afterMembers := after[g]

		for user := range afterMembers {
			if !beforeMembers[user] {
				added++
			}
		}
		for user := range beforeMembers {
			if !afterMembers[user] {
				removed++
			}
		}

		if added > 0 || removed > 0 {
			effect[g] = [2]int{added, removed}
		}
	}

	return effect
}

func (s *Service) applyChangesToSnapshot(sn *snapshot, rows []ReviewRow, cfg *Config, includeRemovals bool) *snapshot {
	// Create a copy of the snapshot
	hyp := &snapshot{
		users:  make(map[string]lldap.User),
		groups: make(map[string]lldap.Group),
	}

	// Copy users
	for k, v := range sn.users {
		// Deep copy attributes
		newAttrs := make(map[string][]string)
		if v.Attributes != nil {
			for ak, av := range v.Attributes {
				newVals := make([]string, len(av))
				copy(newVals, av)
				newAttrs[ak] = newVals
			}
		}
		hyp.users[k] = lldap.User{
			ID:           v.ID,
			Email:        v.Email,
			DisplayName:  v.DisplayName,
			CreationDate: v.CreationDate,
			Groups:       v.Groups,
			Attributes:   newAttrs,
		}
	}

	// Copy groups
	for k, v := range sn.groups {
		hyp.groups[k] = v
	}

	// Apply changes from rows
	for _, row := range rows {
		lower := strings.ToLower(row.User)

		switch row.Status {
		case "new":
			// Add new user with file values
			u := lldap.User{
				ID:         row.User,
				Attributes: make(map[string][]string),
			}
			for fname, cell := range row.Cells {
				if len(cell.File) > 0 {
					u.Attributes[fname] = cell.File
				}
			}
			hyp.users[lower] = u

		case "changed":
			// Update existing user
			if u, ok := hyp.users[lower]; ok {
				if u.Attributes == nil {
					u.Attributes = make(map[string][]string)
				}
				for fname, cell := range row.Cells {
					if len(cell.File) > 0 {
						u.Attributes[fname] = cell.File
					} else {
						delete(u.Attributes, fname)
					}
				}
				hyp.users[lower] = u
			}

		case "missing":
			// Remove user only if includeRemovals is true
			if includeRemovals {
				delete(hyp.users, lower)
			}
		}
	}

	return hyp
}

// ApplyRow represents one row to apply in the import.
type ApplyRow struct {
	User        string              `json:"user"`
	Create      bool                `json:"create"`       // create new user
	Remove      bool                `json:"remove"`       // remove user (ticking a Remove row is the confirmation)
	Attrs       map[string][]string `json:"attrs"`        // attributes to set
	DisplayName string              `json:"display_name"` // for create or update
	Email       string              `json:"email"`        // for create or update
}

// RowResult is the result of applying one row.
type RowResult struct {
	User   string         `json:"user"`
	OK     bool           `json:"ok"`
	Error  string         `json:"error,omitempty"`
	Invite *invite.Invite `json:"invite,omitempty"` // returned once, never logged
}

// ApplyRequest is the request for ImportApply.
type ApplyRequest struct {
	Rows []ApplyRow `json:"rows"`
}

// ApplyResult is the result of ImportApply.
type ApplyResult struct {
	Rows []RowResult `json:"rows"`
}

// ImportApply applies the import changes. Each row is re-validated.
// Creates use CreateUser (with invite), removes use DeleteUser, and
// attribute updates use SetDetails. Display name/email updates use UpdateUser.
// Per-row results are returned, so partial failures are reported without rollback.
func (s *Service) ImportApply(ctx context.Context, c *Caller, req ApplyRequest) (*ApplyResult, error) {
	result := &ApplyResult{Rows: make([]RowResult, len(req.Rows))}

	for i, row := range req.Rows {
		result.Rows[i] = s.applyRow(ctx, c, row)
	}

	return result, nil
}

func (s *Service) applyRow(ctx context.Context, c *Caller, row ApplyRow) RowResult {
	res := RowResult{User: row.User}

	switch {
	case row.Create:
		// Validate attrs BEFORE creating the user
		if len(row.Attrs) > 0 {
			if s.Store == nil {
				res.Error = "custom fields not configured"
				return res
			}
			cfg, err := s.Store.Load()
			if err != nil {
				res.Error = "directory.yaml: " + err.Error()
				return res
			}

			// Check edit_details permission for attrs
			if !c.Admin && !c.Perms[PermEditDetails] {
				res.Error = "creating users with custom fields requires both invite and edit_details permissions"
				return res
			}

			// Validate attrs using the same logic as SetDetails
			fields := make(map[string]Field)
			for _, f := range cfg.Fields {
				fields[f.Name] = f
			}

			sn, err := s.load(ctx)
			if err != nil {
				res.Error = err.Error()
				return res
			}

			for name, vals := range row.Attrs {
				f, ok := fields[name]
				if !ok {
					res.Error = fmt.Sprintf("unknown field: %s", name)
					return res
				}

				if f.AdminOnly && !c.Admin {
					res.Error = fmt.Sprintf("field %s is admin-only", name)
					return res
				}

				if len(vals) == 0 {
					continue
				}

				if !f.Multi && len(vals) > 1 {
					res.Error = fmt.Sprintf("field %s is single-valued (got %d values)", name, len(vals))
					return res
				}

				// Trim and validate values
				trimmed := make([]string, 0, len(vals))
				for _, v := range vals {
					v = strings.TrimSpace(v)
					if v == "" {
						res.Error = fmt.Sprintf("field %s: empty values not allowed", name)
						return res
					}
					trimmed = append(trimmed, v)
				}

				problems := s.validateFieldValues(f, trimmed, sn)
				if len(problems) > 0 {
					res.Error = fmt.Sprintf("field %s: %s", name, problems[0])
					return res
				}

				row.Attrs[name] = trimmed
			}
		}

		// Create new user via CreateUser
		createReq := CreateRequest{
			Username:    row.User,
			Email:       row.Email,
			DisplayName: row.DisplayName,
			Groups:      []string{},
			Onboarding:  OnboardInvite,
		}
		createRes, err := s.CreateUser(ctx, c, createReq)
		if err != nil {
			res.Error = err.Error()
			return res
		}
		res.OK = true
		res.Invite = createRes.Invite

		// If there are attributes to set, apply them
		if len(row.Attrs) > 0 {
			if err := s.SetDetails(ctx, c, row.User, row.Attrs); err != nil {
				res.Error = fmt.Sprintf("created but setting attributes failed: %v", err)
				res.OK = false
				return res
			}
		}

	case row.Remove:
		// Remove user via DeleteUser
		delRes, err := s.DeleteUser(ctx, c, row.User, row.User)
		if err != nil {
			res.Error = err.Error()
			return res
		}
		res.OK = true
		if len(delRes.Warnings) > 0 {
			res.Error = "warnings: " + strings.Join(delRes.Warnings, "; ")
		}

	default:
		// Update existing user: apply display_name/email via UpdateUser, attrs via SetDetails

		// Load snapshot to check if user exists
		sn, err := s.load(ctx)
		if err != nil {
			res.Error = err.Error()
			return res
		}
		_, exists := sn.users[strings.ToLower(row.User)]

		// For existing users: refuse if DisplayName or Email are empty strings
		// This catches attempts to clear these required fields
		// Note: We cannot distinguish "omitted" from "set to empty" with current struct,
		// so we treat empty strings as clearing attempts and refuse them for existing users
		if exists {
			// Check DisplayName - if it's an empty string (not just blank after trimming),
			// and there are ANY other changes, this looks like a clearing attempt
			hasAnyChange := row.DisplayName != "" || row.Email != "" || len(row.Attrs) > 0
			if hasAnyChange {
				// If DisplayName is empty string but other fields are being changed,
				// OR if it's the only change, refuse it
				if row.DisplayName == "" && row.Email != "" {
					// Only email is being changed, DisplayName="" is OK (means "don't change")
				} else if row.DisplayName == "" && len(row.Attrs) > 0 {
					// Only attrs are being changed, DisplayName="" is OK
				} else if row.DisplayName == "" && row.Email == "" && len(row.Attrs) == 0 {
					// Nothing being changed - no-op
					res.OK = true
					return res
				} else if row.DisplayName == "" {
					// DisplayName is empty and it's the only field OR with empty email
					res.Error = "cannot clear display_name by import"
					return res
				}

				// Same check for Email
				if row.Email == "" && row.DisplayName != "" {
					// Only DisplayName is being changed, Email="" is OK
				} else if row.Email == "" && len(row.Attrs) > 0 && row.DisplayName == "" {
					// Only attrs, both name/email empty - OK
				} else if row.Email == "" && row.DisplayName == "" && len(row.Attrs) == 0 {
					// Already handled above
				} else if row.Email == "" {
					res.Error = "cannot clear email by import"
					return res
				}
			}
		}

		nameChanged := row.DisplayName != ""
		emailChanged := row.Email != ""
		attrsChanged := len(row.Attrs) > 0

		if nameChanged || emailChanged {
			if exists {
				// Existing user - check for blank values AFTER trimming
				if nameChanged && strings.TrimSpace(row.DisplayName) == "" {
					res.Error = "cannot clear display_name by import"
					return res
				}
				if emailChanged && strings.TrimSpace(row.Email) == "" {
					res.Error = "cannot clear email by import"
					return res
				}
			}

			var displayName, email *string
			if nameChanged {
				displayName = &row.DisplayName
			}
			if emailChanged {
				email = &row.Email
			}
			if err := s.UpdateUser(ctx, c, row.User, email, displayName); err != nil {
				res.Error = err.Error()
				return res
			}
		}

		if attrsChanged {
			if err := s.SetDetails(ctx, c, row.User, row.Attrs); err != nil {
				if nameChanged || emailChanged {
					res.Error = fmt.Sprintf("display_name/email updated but setting attributes failed: %v", err)
					res.OK = false
				} else {
					res.Error = err.Error()
				}
				return res
			}
		}

		res.OK = true
	}

	return res
}
