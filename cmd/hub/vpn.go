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

const mailUsage = `usage: hub mail drain     (every mail domain starts draining)
       hub mail domains   (each mail domain's state: on, draining or off)`

// mailMain runs `hub mail <args>` against the socket at sock (contract
// §19.10): 0 done, 1 the Hub refused or isn't running, 2 usage.
func mailMain(args []string, stdout, stderr io.Writer, sock string) int {
	if len(args) != 1 || (args[0] != "drain" && args[0] != "domains") {
		fmt.Fprintln(stderr, mailUsage)
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
	method, path := http.MethodGet, "/host/mail/domains"
	if args[0] == "drain" {
		method, path = http.MethodPost, "/host/mail/drain"
	}
	req, _ := http.NewRequest(method, "http://hub"+path, nil)
	res, err := c.Do(req)
	if err != nil {
		fmt.Fprintln(stderr, "the Hub isn't running")
		return 1
	}
	defer res.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
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
