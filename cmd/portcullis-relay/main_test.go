package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRelayCommand(t *testing.T) {
	var out, errb bytes.Buffer
	if rc := Main([]string{"--help"}, &out, &errb, func(string) string { return "" }); rc != 0 || !strings.Contains(out.String(), "RELAY_LISTEN") {
		t.Errorf("--help: %d %q", rc, out.String())
	}
	env := map[string]string{"RELAY_LISTEN": ":8080", "RELAY_TARGET": "immich.web.relay", "RELAY_LINK": "172.31.254.130:3129", "PORTCULLIS_RELAY_TOKEN": "s3cret-token"}
	get := func(k string) string { return env[k] }
	env["RELAY_TARGET"] = "evil"
	errb.Reset()
	if rc := Main(nil, &out, &errb, get); rc != 2 || strings.Contains(errb.String(), "s3cret") {
		t.Errorf("bad target: %d %q", rc, errb.String())
	}
	env["RELAY_LISTEN"] = "8080"
	if rc := Main(nil, &out, &errb, get); rc != 2 {
		t.Errorf("bad listen: %d", rc)
	}
	if rc := Main([]string{"extra"}, &out, &errb, func(k string) string { return map[string]string{"RELAY_LISTEN": ":1"}[k] }); rc != 2 {
		t.Errorf("extra argument: %d", rc)
	}
}
