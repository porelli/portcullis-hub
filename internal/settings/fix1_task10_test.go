package settings

import (
	"strings"
	"testing"
)

// Task 10 fix round 1.

// TestParseHookReportOneDocument: data after the JSON document is refused.
func TestParseHookReportOneDocument(t *testing.T) {
	for _, out := range []string{
		`PORTCULLIS-REPORT {"version": 1} {"version": 1}`,
		`PORTCULLIS-REPORT {"version": 1}x`,
		`PORTCULLIS-REPORT {"version": 1} []`,
	} {
		if _, err := ParseHookReport([]byte(out)); err == nil || !strings.Contains(err.Error(), "data after") {
			t.Errorf("%q: err = %v", out, err)
		}
	}
	if _, err := ParseHookReport([]byte("PORTCULLIS-REPORT {\"version\": 1}  \r\n")); err != nil {
		t.Errorf("trailing whitespace refused: %v", err)
	}
}

// TestEncodeTSVChecksEveryField: a tab or newline in a key, user, field
// or group name is refused, naming it.
func TestEncodeTSVChecksEveryField(t *testing.T) {
	cases := map[string]func(d *DataFileDoc){
		"group name": func(d *DataFileDoc) {
			d.Groups["seats"] = []GroupRecordOut{{Group: "office\tmilan", Value: 3}}
		},
		"group key":   func(d *DataFileDoc) { d.Groups["se\tats"] = []GroupRecordOut{{Group: "g", Value: 3}} },
		"value key":   func(d *DataFileDoc) { d.Values["a\tb"] = "x" },
		"person":      func(d *DataFileDoc) { d.People["al\nice"] = map[string]any{"uid": 1} },
		"field":       func(d *DataFileDoc) { d.People["alice"] = map[string]any{"u\tid": 1} },
		"entry field": func(d *DataFileDoc) { d.Entries["e\tx"] = []EntryOut{{User: "alice", Value: "v"}} },
		"entry user":  func(d *DataFileDoc) { d.Entries["ext"] = []EntryOut{{User: "al\tice", Value: "v"}} },
		"instance":    func(d *DataFileDoc) { d.Instance = "a\tb" },
	}
	for name, mutate := range cases {
		d := NewDataFileDoc("smb")
		mutate(&d)
		if _, err := EncodeTSV(d); err == nil || !strings.Contains(err.Error(), "tab or newline") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	d := NewDataFileDoc("smb")
	d.Groups["seats"] = []GroupRecordOut{{Group: "office_milan", Value: 3}}
	if _, err := EncodeTSV(d); err != nil {
		t.Errorf("plain names refused: %v", err)
	}
}
