package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/httpapi"
	"github.com/portcullis/hub/internal/hub"
)

// `hub vpn …` (contract §16): the host control socket's only clients,
// run by `./portcullis vpn …` inside the Hub container. The public key
// comes on stdin (never argv); the private key never reaches the Hub.

// hostSocket is the control socket (httpapi.HostSocketPath).
const hostSocket = httpapi.HostSocketPath

const vpnUsage = `usage: hub vpn add-device --user U --name N   (public key on stdin; config JSON on stdout)
       hub vpn devices [--user U]
       hub vpn revoke <device-id>
       hub vpn host-info`

const mailUsage = `usage: hub mail <command>   (contract §19.10; a body is one JSON object on stdin; JSON on stdout)
       hub mail provider                    the wired provider and the warning
       hub mail install    < {"template", "source", "confirm"}   install and wire (answers the op)
       hub mail unwire     < {"drain": true|false}               unwire (answers the op)
       hub mail op         < {"instance", "op_id"}               an op's state (running, ok, error)
       hub mail status                      the Hub's view of mail
       hub mail dns-main                    the validated main-domain mail set and its rules
       hub mail tls        < {"spki_sha256": [...], "not_after"} record the certificate, reload the provider
       hub mail test       < {"to"}         a test message
       hub mail backup                      a backup of the provider (reason core)
       hub mail restore    < {"archive"}    restore the provider from an archive (answers the op)
       hub mail action     < {"name", "domain"}   dkim-rotate, dmarc-promote or mtasts-enforce
       hub mail drain                       every mail domain starts draining
       hub mail domains                     each mail domain's state`

// mailCommands: method, path and whether a body is read from stdin. An
// op (install, unwire, restore) answers OpStarted at once; the caller
// polls `hub mail op` for its terminal state (core interface H6, Ruling
// R-H6).
var mailCommands = map[string]struct {
	method, path string
	body         bool
	timeout      time.Duration
}{
	"provider": {http.MethodGet, "/host/mail/provider", false, time.Minute},
	"install":  {http.MethodPost, "/host/mail/install", true, time.Minute},
	// install-preview {template, source}: the instance install would wire
	// ({instance, creates}; L3).
	"install-preview": {http.MethodPost, "/host/mail/install/preview", true, time.Minute},
	"unwire":          {http.MethodPost, "/host/mail/unwire", true, time.Minute},
	"op":              {http.MethodGet, "/host/mail/op", true, time.Minute},
	"status":          {http.MethodGet, "/host/mail/status", false, 2 * time.Minute},
	"dns-main":        {http.MethodGet, "/host/mail/dns/main", false, time.Minute},
	"tls":             {http.MethodPost, "/host/mail/tls", true, time.Minute},
	"test":            {http.MethodPost, "/host/mail/test", true, time.Minute},
	"backup":          {http.MethodPost, "/host/mail/backup", false, 2 * time.Hour},
	"restore":         {http.MethodPost, "/host/mail/restore", true, hub.HostLockWait + 3*time.Minute},
	"action":          {http.MethodPost, "/host/mail/action", true, time.Minute},
	"drain":           {http.MethodPost, "/host/mail/drain", false, time.Minute},
	"domains":         {http.MethodGet, "/host/mail/domains", false, time.Minute},
}

// mailMain runs `hub mail <args>` against the socket at sock (contract
// §19.10): 0 done, 1 the Hub refused or isn't running (the text on
// stderr), 2 usage or a bad body.
func mailMain(args []string, stdin io.Reader, stdout, stderr io.Writer, sock string) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, mailUsage)
		return 2
	}
	cmd, ok := mailCommands[args[0]]
	if !ok {
		fmt.Fprintln(stderr, mailUsage)
		return 2
	}
	path := cmd.path
	var body []byte
	if cmd.body {
		b, err := io.ReadAll(io.LimitReader(stdin, 64<<10+1))
		var obj map[string]json.RawMessage
		if err != nil || len(b) > 64<<10 || json.Unmarshal(b, &obj) != nil || obj == nil {
			fmt.Fprintln(stderr, "hub mail "+args[0]+": the body on stdin must be one JSON object")
			return 2
		}
		body = b
		if args[0] == "op" {
			var q struct {
				Instance string `json:"instance"`
				OpID     string `json:"op_id"`
			}
			d := json.NewDecoder(bytes.NewReader(b))
			d.DisallowUnknownFields()
			if d.Decode(&q) != nil || q.Instance == "" || q.OpID == "" {
				fmt.Fprintln(stderr, `hub mail op: the body must be {"instance", "op_id"}`)
				return 2
			}
			path += "?instance=" + url.QueryEscape(q.Instance) + "&op_id=" + url.QueryEscape(q.OpID)
			body = nil
		}
	}
	if fi, err := os.Stat(sock); err != nil || fi.Mode()&os.ModeSocket == 0 {
		fmt.Fprintln(stderr, "the Hub isn't running")
		return 1
	}
	c := &http.Client{Timeout: cmd.timeout, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", sock)
	}}}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, _ := http.NewRequest(cmd.method, "http://hub"+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.Do(req)
	if err != nil {
		fmt.Fprintln(stderr, "the Hub isn't running")
		return 1
	}
	defer res.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if res.StatusCode >= 300 {
		fmt.Fprintln(stderr, strings.TrimSpace(string(out)))
		return 1
	}
	stdout.Write(out)
	return 0
}

// vpnMain runs `hub vpn <args>` against the socket at sock; it returns
// the exit code (1: the Hub refused or isn't running, 2: usage).
func vpnMain(args []string, stdin io.Reader, stdout, stderr io.Writer, sock string) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, vpnUsage)
		return 2
	}
	if fi, err := os.Stat(sock); err != nil || fi.Mode()&os.ModeSocket == 0 {
		fmt.Fprintln(stderr, "the Hub isn't running")
		return 1
	}
	c := &http.Client{Timeout: time.Minute, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", sock)
	}}}
	do := func(method, path string, body []byte) int {
		req, _ := http.NewRequest(method, "http://hub"+path, bytes.NewReader(body))
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		res, err := c.Do(req)
		if err != nil {
			fmt.Fprintln(stderr, "the Hub isn't running")
			return 1
		}
		defer res.Body.Close()
		out, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
		if res.StatusCode >= 300 {
			fmt.Fprintln(stderr, strings.TrimSpace(string(out)))
			return 1
		}
		stdout.Write(out)
		return 0
	}
	fs := flag.NewFlagSet("hub vpn "+args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	user := fs.String("user", "", "the person")
	name := fs.String("name", "", "the device name")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	switch args[0] {
	case "add-device":
		if *user == "" || *name == "" || fs.NArg() != 0 {
			fmt.Fprintln(stderr, vpnUsage)
			return 2
		}
		key, err := io.ReadAll(io.LimitReader(stdin, 256))
		if err != nil {
			fmt.Fprintln(stderr, "reading the public key from stdin failed")
			return 1
		}
		body, _ := json.Marshal(map[string]string{"user": *user, "name": *name, "public_key": strings.TrimSpace(string(key))})
		return do(http.MethodPost, "/host/vpn/devices", body)
	case "devices":
		if fs.NArg() != 0 || *name != "" {
			fmt.Fprintln(stderr, vpnUsage)
			return 2
		}
		q := ""
		if *user != "" {
			q = "?user=" + url.QueryEscape(*user)
		}
		return do(http.MethodGet, "/host/vpn/devices"+q, nil)
	case "revoke":
		if fs.NArg() != 1 || *user != "" || *name != "" {
			fmt.Fprintln(stderr, vpnUsage)
			return 2
		}
		return do(http.MethodDelete, "/host/vpn/devices/"+url.PathEscape(fs.Arg(0)), nil)
	case "host-info":
		if fs.NArg() != 0 || *user != "" || *name != "" {
			fmt.Fprintln(stderr, vpnUsage)
			return 2
		}
		return do(http.MethodGet, "/host/vpn/info", nil)
	}
	fmt.Fprintln(stderr, vpnUsage)
	return 2
}
