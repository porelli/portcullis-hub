package usage

import (
	"encoding/csv"
	"io"
	"strconv"
)

// CSVCell escapes a cell against formula injection: a cell starting with
// =, +, -, @, a tab or a CR is prefixed with ' (contract §11.11).
func CSVCell(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

// WriteCSV writes header and rows with encoding/csv, every cell through
// CSVCell.
func WriteCSV(w io.Writer, header []string, rows [][]string) error {
	cw := csv.NewWriter(w)
	esc := func(r []string) []string {
		out := make([]string, len(r))
		for i, c := range r {
			out[i] = CSVCell(c)
		}
		return out
	}
	if err := cw.Write(esc(header)); err != nil {
		return err
	}
	for _, r := range rows {
		if err := cw.Write(esc(r)); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// Int is a CSV number cell: "" for nil.
func Int(v *int64) string {
	if v == nil {
		return ""
	}
	return strconv.FormatInt(*v, 10)
}

// Float is a CSV number cell: "" for nil.
func Float(v *float64) string {
	if v == nil {
		return ""
	}
	return strconv.FormatFloat(*v, 'f', -1, 64)
}
