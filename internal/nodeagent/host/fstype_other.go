//go:build !linux

package host

import "errors"

// fsType: Linux only (the nodeagent runs on Linux; tests set Config.FSType).
func fsType(string) (string, error) { return "", errors.New("not Linux") }
