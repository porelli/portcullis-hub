package jsonstrict

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

type inner struct {
	A string `json:"a"`
	B int    `json:"b,omitempty"`
}

type outer struct {
	Name  string            `json:"name"`
	At    time.Time         `json:"at"`
	IP    netip.Addr        `json:"ip"`
	Net   netip.Prefix      `json:"net"`
	Items []inner           `json:"items"`
	Tags  map[string]string `json:"tags,omitempty"`
}

const good = `{"name":"x","at":"2026-11-15T10:00:00Z","ip":"10.214.0.10","net":"10.214.0.0/24","items":[{"a":"1"}],"tags":{"k":"v"}}`

func TestDecode(t *testing.T) {
	var o outer
	if err := Decode([]byte(good), &o); err != nil {
		t.Fatal(err)
	}
	if o.IP != netip.MustParseAddr("10.214.0.10") || o.Net.Bits() != 24 || o.Items[0].A != "1" {
		t.Errorf("decoded %+v", o)
	}
	for name, c := range map[string]struct{ doc, want string }{
		"unknown key":          {strings.Replace(good, `"name":"x"`, `"name":"x","extra":1`, 1), `unknown field "extra"`},
		"nested unknown":       {strings.Replace(good, `{"a":"1"}`, `{"a":"1","z":2}`, 1), `unknown field "z"`},
		"duplicate key":        {strings.Replace(good, `"name":"x"`, `"name":"x","name":"y"`, 1), `duplicate key "name"`},
		"nested duplicate":     {strings.Replace(good, `{"a":"1"}`, `{"a":"1","a":"2"}`, 1), `duplicate key "a"`},
		"map duplicate":        {strings.Replace(good, `{"k":"v"}`, `{"k":"v","k":"w"}`, 1), `duplicate key "k"`},
		"missing field":        {strings.Replace(good, `"name":"x",`, ``, 1), `missing field "name"`},
		"case-folded key":      {strings.Replace(good, `"name":"x"`, `"NAME":"x"`, 1), `unknown field "NAME"`},
		"null":                 {strings.Replace(good, `"name":"x"`, `"name":null`, 1), `$.name: null`},
		"null list":            {strings.Replace(good, `[{"a":"1"}]`, `null`, 1), `$.items: null`},
		"trailing data":        {good + ` {}`, `trailing`},
		"bad addr":             {strings.Replace(good, `10.214.0.10`, `10.214.0.300`, 1), `does not decode`},
		"addr as object":       {strings.Replace(good, `"10.214.0.10"`, `{}`, 1), `wrong type`},
		"wrong type":           {strings.Replace(good, `"name":"x"`, `"name":1`, 1), `wrong type`},
		"not an object":        {`[]`, `not an object`},
		"not a list":           {strings.Replace(good, `[{"a":"1"}]`, `{}`, 1), `not a list`},
		"invalid json":         {`{"name":`, `not valid JSON`},
		"top-level null":       {`null`, `$: null`},
		"value never echoed":   {strings.Replace(good, `"name":"x"`, `"name":"s3cret","name":"s3cret"`, 1), `duplicate key`},
		"nested list null obj": {strings.Replace(good, `[{"a":"1"}]`, `[null]`, 1), `$.items[0]: null`},
	} {
		var o outer
		err := Decode([]byte(c.doc), &o)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err %v, want %q", name, err, c.want)
		}
		if err != nil && strings.Contains(err.Error(), "s3cret") {
			t.Errorf("%s: the error echoes a value: %v", name, err)
		}
	}
}
