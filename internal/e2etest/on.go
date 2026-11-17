//go:build e2etest

package e2etest

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

// Enabled: this binary was built with -tags e2etest.
const Enabled = true

// marker is in e2etest binaries only (CI greps the default ones for it).
var marker = "PORTCULLIS-E2ETEST-BUILD-HOOKS"

// Marker is the e2etest build's marker string.
func Marker() string { return marker }

// ClockOffset is HUB_DEV_CLOCK_OFFSET_FILE's reader (nil unset): the
// duration in the file, re-read at most once per second.
func ClockOffset(getenv func(string) string) (func() time.Duration, error) {
	p := getenv(EnvClockOffset)
	if p == "" {
		return nil, nil
	}
	return OffsetReader(p, time.Now), nil
}

// OffsetReader reads path's duration, cached for a second (now: the
// real clock). Missing or empty: 0; unparsable: logged once per value, 0.
func OffsetReader(path string, now func() time.Time) func() time.Duration {
	var (
		mu     sync.Mutex
		at     time.Time
		cur    time.Duration
		logged string
	)
	return func() time.Duration {
		mu.Lock()
		defer mu.Unlock()
		t := now()
		if !at.IsZero() && t.Sub(at) < time.Second && t.Sub(at) >= 0 {
			return cur
		}
		at, cur = t, 0
		b, err := os.ReadFile(path)
		v := strings.TrimSpace(string(b))
		if err != nil || v == "" {
			return 0
		}
		d, err := time.ParseDuration(v)
		if err != nil {
			if logged != v {
				logged = v
				log.Printf("%s: %q isn't a Go duration: no clock offset", EnvClockOffset, v)
			}
			return 0
		}
		cur = d
		return cur
	}
}

// OversizeInfo is AGENT_TEST_OVERSIZE_INFO=1 (anything else set: refused).
func OversizeInfo(getenv func(string) string) (bool, error) {
	switch v := getenv(EnvOversizeInfo); v {
	case "":
		return false, nil
	case "1":
		return true, nil
	default:
		return false, fmt.Errorf("%s must be 1", EnvOversizeInfo)
	}
}
