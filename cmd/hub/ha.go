package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// `hub ha checklist` (contract §20.1 "The CLI twins"): the HA page's
// answer (GET /host/ha) from the running Hub over the host control
// socket, run by `./portcullis ha status|enable` with `kubectl exec`.
// Read-only; turning HA on is the CLI's own operation.

const haUsage = `usage: hub ha checklist`

// haAnswerMax bounds the answer (a longer one is cut: never printed in
// part, a parser would read half a JSON). A variable: tests.
var haAnswerMax = 4 << 20

// haTimeout bounds the call (2 min, as the other twins).
var haTimeout = 2 * time.Minute

func haMain(args []string, stdout, stderr io.Writer, sock string) int {
	if len(args) != 1 || args[0] != "checklist" {
		fmt.Fprintln(stderr, haUsage)
		return 2
	}
	if fi, err := os.Stat(sock); err != nil || fi.Mode()&os.ModeSocket == 0 {
		fmt.Fprintln(stderr, "the Hub isn't running")
		return 1
	}
	c := &http.Client{Timeout: haTimeout, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", sock)
	}}}
	res, err := c.Get("http://hub/host/ha")
	if err != nil {
		var ue *url.Error
		var oe *net.OpError
		switch {
		case errors.As(err, &oe) && oe.Op == "dial":
			fmt.Fprintln(stderr, "the Hub isn't running")
		case errors.As(err, &ue) && ue.Timeout():
			fmt.Fprintln(stderr, "the Hub is still working: run `hub ha checklist` again")
		default:
			fmt.Fprintf(stderr, "the Hub's answer was cut: %v\n", err)
		}
		return 1
	}
	defer res.Body.Close()
	out, err := io.ReadAll(io.LimitReader(res.Body, int64(haAnswerMax)+1))
	switch {
	case err != nil:
		fmt.Fprintf(stderr, "the Hub's answer was cut: %v\n", err)
		return 1
	case len(out) > haAnswerMax:
		fmt.Fprintf(stderr, "the Hub's answer was cut: over %d bytes\n", haAnswerMax)
		return 1
	}
	if res.StatusCode >= 300 {
		fmt.Fprintln(stderr, strings.TrimSpace(string(out)))
		return 1
	}
	stdout.Write(out)
	return 0
}
