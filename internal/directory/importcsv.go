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
// It detects the separator (comma or semicolon) from the header line,
// handles BOM, CRLF, and quoted newlines.
// Refuses files > 10,000 rows or > 64 columns.
func ParseCSV(r io.Reader) (header []string, rows [][]string, err error) {
	// Read all data (limited by HTTP layer to 5 MB)
	data, err := io.ReadAll(io.LimitReader(r, maxCSVBytes+1))
	if err != nil {
		return nil, nil, fmt.Errorf("read CSV: %w", err)
	}
	if len(data) > maxCSVBytes {
		return nil, nil, invalid("CSV file too large (max 5 MB)")
	}

	// Strip BOM if present
	data = bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})

	// Detect separator from first line
	separator := ','
	firstLine := data
	if idx := bytes.IndexByte(data, '\n'); idx >= 0 {
		firstLine = data[:idx]
	}
	if bytes.Count(firstLine, []byte{';'}) > bytes.Count(firstLine, []byte{','}) {
		separator = ';'
	}

	// Parse CSV
	reader := csv.NewReader(bytes.NewReader(data))
	reader.Comma = separator
	reader.TrimLeadingSpace = true

	records, err := reader.ReadAll()
	if err != nil {
		return nil, nil, invalid("parse CSV: %v", err)
	}

	if len(records) == 0 {
		return nil, nil, invalid("CSV file is empty")
	}

	// Check limits
	if len(records) > maxCSVRows+1 { // +1 for header
		return nil, nil, invalid("CSV file has too many rows (max %d)", maxCSVRows)
	}
	if len(records[0]) > maxCSVColumns {
		return nil, nil, invalid("CSV file has too many columns (max %d)", maxCSVColumns)
	}

	// Normalize header (lowercase, trim)
	header = make([]string, len(records[0]))
	seen := make(map[string]bool)
	for i, h := range records[0] {
		h = strings.TrimSpace(h)
		h = strings.ToLower(h)
		header[i] = h
		if h != "" && seen[h] {
			return nil, nil, invalid("duplicate column header: %q", h)
		}
		seen[h] = true
	}

	// Check for required username column
	hasUsername := false
	for _, h := range header {
		if h == "username" {
			hasUsername = true
			break
		}
	}
	if !hasUsername {
		return nil, nil, invalid("CSV must have a %q column", "username")
	}

	// Return rows (skip header)
	rows = records[1:]
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

	// Build column map
	colMap := make(map[string]int) // field name -> column index
	usernameCol := -1
	displayNameCol := -1
	emailCol := -1

	for i, h := range header {
		switch h {
		case "username":
			usernameCol = i
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
		if usernameCol >= 0 && usernameCol < len(row) {
			user := strings.TrimSpace(row[usernameCol])
			lower := strings.ToLower(user)
			fileUsers[lower] = append(fileUsers[lower], user)
		}
	}

	// Process each row in the file
	for _, row := range rows {
		if usernameCol >= 0 && usernameCol < len(row) {
			user := strings.TrimSpace(row[usernameCol])
			rr := s.reviewRow(ctx, c, user, row, header, colMap, displayNameCol, emailCol, sn, cfg, fields, fileUsers)
			review.Rows = append(review.Rows, rr)
		}
	}

	// Add "missing" rows: users in LLDAP but not in the file
	for user := range sn.users {
		lower := strings.ToLower(user)
		if _, inFile := fileUsers[lower]; !inFile {
			// Skip protected accounts
			if s.checkTarget(user) != nil {
				continue
			}
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
			review.Rows = append(review.Rows, rr)
		}
	}

	// Compute Effect on rule groups
	if cfg != nil {
		review.Effect = s.computeEffect(ctx, cfg, sn, review.Rows, time.Now())
	}

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

	// Check for duplicate usernames in file
	if len(fileUsers[lower]) > 1 {
		rr.Problems = append(rr.Problems, fmt.Sprintf("duplicate username in file: %s", strings.Join(fileUsers[lower], ", ")))
	}

	u, exists := sn.users[lower]
	if exists {
		rr.Status = "same" // will be changed to "changed" if differences found
	}

	changed := false

	// Check display_name and email
	if displayNameCol >= 0 && displayNameCol < len(row) {
		fileVal := strings.TrimSpace(row[displayNameCol])
		if exists && u.DisplayName != fileVal {
			changed = true
		}
	}
	if emailCol >= 0 && emailCol < len(row) {
		fileVal := strings.TrimSpace(row[emailCol])
		if exists && u.Email != fileVal {
			changed = true
		}
	}

	// Process custom fields
	for fname, col := range colMap {
		f := fields[fname]
		var fileVals []string

		if col < len(row) {
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
		}

		var currentVals []string
		if exists && u.Attributes != nil {
			if vals, ok := u.Attributes[fname]; ok {
				currentVals = vals
			}
		}

		// Build cell
		rr.Cells[fname] = Cell{Current: currentVals, File: fileVals}

		// Check if changed
		if !stringSliceEqual(currentVals, fileVals) {
			changed = true
		}

		// Validate file values
		problems := s.validateFieldValues(f, fileVals, sn)
		for _, p := range problems {
			rr.Problems = append(rr.Problems, fmt.Sprintf("field %s: %s", fname, p))
		}

		// Check permission for AdminOnly fields
		if f.AdminOnly && !c.Admin && len(fileVals) > 0 {
			rr.Problems = append(rr.Problems, fmt.Sprintf("field %s is admin-only", fname))
		}
	}

	if exists && changed {
		rr.Status = "changed"
	}

	// Check if caller can target this user (for delegates)
	if !c.Admin {
		if err := s.checkDelegateTarget(c, user, sn, cfg); err != nil {
			rr.Problems = append(rr.Problems, fmt.Sprintf("only an admin can change %s", user))
		}
	}

	// New user validation
	if !exists {
		// Check invite permission
		if !c.Admin && !c.Perms[PermInvite] {
			rr.Problems = append(rr.Problems, "creating new users requires the invite permission")
		}

		// Check for tombstone (delegates)
		if !c.Admin && cfg != nil {
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

	// Missing user - check remove permission
	if rr.Status == "missing" && !c.Admin && !c.Perms[PermRemove] {
		rr.Problems = append(rr.Problems, "removing users requires the remove permission")
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

func (s *Service) computeEffect(ctx context.Context, cfg *Config, sn *snapshot, rows []ReviewRow, now time.Time) map[string][2]int {
	// Build a hypothetical snapshot with the changes applied
	hypothetical := s.applyChangesToSnapshot(sn, rows, cfg)

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

func (s *Service) applyChangesToSnapshot(sn *snapshot, rows []ReviewRow, cfg *Config) *snapshot {
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
			// Remove user
			delete(hyp.users, lower)
		}
	}

	return hyp
}

// ApplyRow represents one row to apply in the import.
type ApplyRow struct {
	User        string              `json:"user"`
	Create      bool                `json:"create"`       // create new user
	Remove      bool                `json:"remove"`       // remove user
	Attrs       map[string][]string `json:"attrs"`        // attributes to set
	DisplayName string              `json:"display_name"` // for create
	Email       string              `json:"email"`        // for create
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
// attribute updates use SetUserAttributes. Per-row results are returned,
// so partial failures are reported without rollback.
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
		// Update attributes via SetDetails
		if len(row.Attrs) > 0 {
			if err := s.SetDetails(ctx, c, row.User, row.Attrs); err != nil {
				res.Error = err.Error()
				return res
			}
		}
		res.OK = true
	}

	return res
}
