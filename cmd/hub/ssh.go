package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// `hub ssh status` (contract §18): `./portcullis status`'s SSH block over
// the host control socket — on/off, the CA fingerprints, the problems
// enroll reports (mounts, caps, CA key types, the host role) and the
// managed hosts with their last sync. Read-only.

const sshUsage = `usage: hub ssh status   (JSON on stdout)`

// sshMain runs `hub ssh <args>` against the socket at sock: 0 done, 1 the
// Hub refused or isn't running, 2 usage.
func sshMain(args []string, stdout, stderr io.Writer, sock string) int {
	if len(args) != 1 || args[0] != "status" {
		fmt.Fprintln(stderr, sshUsage)
		return 2
	}
	if fi, err := os.Stat(sock); err != nil || fi.Mode()&os.ModeSocket == 0 {
		fmt.Fprintln(stderr, "the Hub isn't running")
		return 1
	}
	c := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", sock)
	}}}
	res, err := c.Get("http://hub/host/ssh/status")
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
