//go:build windows

package host

import "io/fs"

func fileUID(fs.FileInfo) (int, bool) { return 0, false }
