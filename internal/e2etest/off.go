//go:build !e2etest

package e2etest

import (
	"errors"
	"time"
)

// Enabled: this binary was built with -tags e2etest.
const Enabled = false

// Marker is the e2etest build's marker string ("" here: a default build
// carries none; CI checks the default binaries for it).
func Marker() string { return "" }

// ClockOffset refuses a set HUB_DEV_CLOCK_OFFSET_FILE: a default build
// has no clock hook (nil: no offset).
func ClockOffset(getenv func(string) string) (func() time.Duration, error) {
	if getenv(EnvClockOffset) != "" {
		return nil, errors.New(EnvClockOffset + " needs an e2etest build")
	}
	return nil, nil
}

// OversizeInfo refuses a set AGENT_TEST_OVERSIZE_INFO.
func OversizeInfo(getenv func(string) string) (bool, error) {
	if getenv(EnvOversizeInfo) != "" {
		return false, errors.New(EnvOversizeInfo + " needs an e2etest build")
	}
	return false, nil
}
