//go:build windows

package host

import "errors"

func hup(int) error { return errors.New("windows hosts: follow the manual steps in the docs") }
