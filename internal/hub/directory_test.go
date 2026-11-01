package hub

import "testing"

func TestDirectoryApps(t *testing.T) {
	f := newFixture(t)
	apps := f.h.DirectoryApps()
	if len(apps) != 2 {
		t.Fatalf("directory apps = %+v", apps)
	}
	for _, a := range apps {
		if a.ID == "grafana" && (a.AccessGroup != "users_grafana" || a.AdminGroup != "admin_grafana" || a.Enabled) {
			t.Errorf("grafana = %+v", a)
		}
	}
}
