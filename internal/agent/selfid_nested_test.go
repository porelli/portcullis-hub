package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The agent's own id in Docker, Podman and a nested engine (core's
// dind e2e worker): the /etc/hostname, /etc/hosts and /etc/resolv.conf
// binds name the innermost container; they win over the other ids.
func TestSelfIDFromHostMounts(t *testing.T) {
	inner, outer := strings.Repeat("a1", 32), strings.Repeat("b2", 32)
	docker := func(id, base string) string {
		return "512 500 8:1 " + base + "/containers/" + id + "/resolv.conf /etc/resolv.conf rw,relatime - ext4 /dev/sda1 rw\n" +
			"513 500 8:1 " + base + "/containers/" + id + "/hostname /etc/hostname rw,relatime - ext4 /dev/sda1 rw\n" +
			"514 500 8:1 " + base + "/containers/" + id + "/hosts /etc/hosts rw,relatime - ext4 /dev/sda1 rw\n"
	}
	for name, c := range map[string]struct {
		mountinfo, cgroup, want string
		wantErr                 bool
	}{
		"docker": {mountinfo: "500 1 0:50 / / rw - overlay overlay rw,lowerdir=/var/lib/docker/overlay2/l/X\n" + docker(inner, "/var/lib/docker"),
			cgroup: "0::/\n", want: inner},
		"podman": {mountinfo: "600 1 0:60 / / rw - overlay overlay rw\n" +
			"601 600 0:22 /containers/storage/overlay-containers/" + inner + "/userdata/hostname /etc/hostname rw - tmpfs tmpfs rw\n" +
			"602 600 0:22 /containers/storage/overlay-containers/" + inner + "/userdata/hosts /etc/hosts rw - tmpfs tmpfs rw\n" +
			"603 600 0:22 /containers/storage/overlay-containers/" + inner + "/userdata/resolv.conf /etc/resolv.conf rw - tmpfs tmpfs rw\n",
			cgroup: "0::/machine.slice/libpod-" + inner + ".scope\n", want: inner},
		// dind: the inner engine's root sits in the outer container, whose
		// id shows in the overlay paths and the cgroup.
		"nested dind": {mountinfo: "700 1 0:70 / / rw - overlay overlay rw,lowerdir=/var/lib/docker/overlay2/" + outer + "/diff\n" +
			"701 700 8:1 /var/lib/docker/containers/" + outer + "/hostname /etc/host-outer rw - ext4 /dev/sda1 rw\n" +
			docker(inner, "/var/lib/docker/volumes/dind/_data"),
			cgroup: "0::/docker/" + outer + "/docker/" + inner + "\n", want: inner},
		// The binds disagree: the old rule, and here it's ambiguous.
		"disagreeing": {mountinfo: "800 1 8:1 /var/lib/docker/containers/" + inner + "/hostname /etc/hostname rw - ext4 /dev/sda1 rw\n" +
			"801 1 8:1 /var/lib/docker/containers/" + outer + "/hosts /etc/hosts rw - ext4 /dev/sda1 rw\n",
			cgroup: "0::/\n", wantErr: true},
		// No host binds: the old rule (one id: fine).
		"no binds, one id": {mountinfo: "900 1 0:90 / / rw - overlay overlay rw,upperdir=/var/lib/docker/containers/" + inner + "/x\n", cgroup: "", want: inner},
		"no binds, two ids": {mountinfo: "900 1 0:90 / / rw - overlay overlay rw,upperdir=/var/lib/docker/containers/" + inner + "/x\n",
			cgroup: "0::/docker/" + outer + "\n", wantErr: true},
	} {
		got, err := selfIDFrom([]byte(c.mountinfo), []byte(c.cgroup))
		if c.wantErr {
			if err == nil || !strings.Contains(err.Error(), "ambiguous") {
				t.Errorf("%s: %q %v, want ambiguous", name, got, err)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%s: %q %v, want %q", name, got, err, c.want)
		}
	}
	// Through the files, and AGENT_CONTAINER_ID still overrides.
	proc := t.TempDir()
	os.MkdirAll(filepath.Join(proc, "self"), 0o755)
	os.WriteFile(filepath.Join(proc, "self", "mountinfo"), []byte(docker(inner, "/var/lib/docker")+"1 1 0:1 /var/lib/docker/overlay2/"+outer+" / rw - overlay o rw\n"), 0o644)
	os.WriteFile(filepath.Join(proc, "self", "cgroup"), []byte("0::/docker/"+outer+"\n"), 0o644)
	if got, err := SelfContainerID(func(string) string { return "" }, proc); err != nil || got != inner {
		t.Errorf("files: %q %v", got, err)
	}
	if got, _ := SelfContainerID(func(k string) string {
		if k == "AGENT_CONTAINER_ID" {
			return outer
		}
		return ""
	}, proc); got != outer {
		t.Errorf("override: %q", got)
	}
}
