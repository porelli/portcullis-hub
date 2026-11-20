package servers

import (
	"os"
	"reflect"
	"testing"

	"github.com/portcullis/hub/internal/jsonstrict"
)

// TestSiteRolesVectors: every vector of site_roles_vectors.json gives its
// role and warnings, or its exact refusal (the 5-server cap, the sites
// rule and the even-count warning of the Task 2 rulings).
func TestSiteRolesVectors(t *testing.T) {
	b, err := os.ReadFile("testdata/site_roles_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []siteRolesVector
	if err := jsonstrict.Decode(b, &vs); err != nil {
		t.Fatal(err)
	}
	for _, v := range vs {
		var cl []ClusterNode
		for _, c := range v.Cluster {
			cl = append(cl, ClusterNode{ID: c.ID, Site: c.Site, Role: c.Role, Healthy: c.Healthy})
		}
		role, warns, err := SuggestRole(cl, NewNode{Site: v.New.Site, RTTms: v.New.RTTms, Override: v.New.Override})
		if v.WantError != "" {
			if err == nil || err.Error() != v.WantError {
				t.Errorf("%s: %v, want %q", v.Name, err, v.WantError)
			}
			continue
		}
		if err != nil || role != v.Want.V.Role || !reflect.DeepEqual(warns, v.Want.V.Warnings) {
			t.Errorf("%s: %s %q %v, want %s %q", v.Name, role, warns, err, v.Want.V.Role, v.Want.V.Warnings)
		}
	}
}
