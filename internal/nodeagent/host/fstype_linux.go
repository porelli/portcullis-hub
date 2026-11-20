//go:build linux

package host

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// fsType names the file system holding path by its statfs magic.
func fsType(path string) (string, error) {
	var s unix.Statfs_t
	if err := unix.Statfs(path, &s); err != nil {
		return "", err
	}
	switch uint64(s.Type) {
	case 0x2fc12fc1:
		return "zfs", nil
	case 0x9123683e:
		return "btrfs", nil
	case 0xef53:
		return "ext4", nil
	case 0x58465342:
		return "xfs", nil
	case 0x01021994:
		return "tmpfs", nil
	case 0x794c7630:
		return "overlay", nil
	default:
		return fmt.Sprintf("fs 0x%x", uint64(s.Type)), nil
	}
}
