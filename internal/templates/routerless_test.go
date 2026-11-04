package templates

import (
	"strings"
	"testing"
)

// Router-less templates (contract §3): only method custom may have zero
// HTTP routers (F48); such a template with group_access and an access
// group is what person_secret / person_id need (F1).

func TestRouterlessCustomDiscovered(t *testing.T) {
	tm, err := build("files", "src", "", []byte(smbHead), []byte(smbCompose), "example.org", nil)
	if err != nil {
		t.Fatalf("router-less custom template refused: %v", err)
	}
	if !tm.Manifest.Routerless() {
		t.Error("Routerless() = false for custom with zero routers")
	}
	if len(tm.Subdomains) != 0 || len(tm.HostRouters) != 0 {
		t.Errorf("hosts of a router-less template: %v %v", tm.Subdomains, tm.HostRouters)
	}
	// Instance views keep it.
	in, err := tm.Instance("files-office", nil, "example.org")
	if err != nil {
		t.Fatal(err)
	}
	if !in.Manifest.Routerless() {
		t.Error("an instance view lost Routerless()")
	}
	// With its file-sharing options.
	if _, err := build("files", "src", "", []byte(smb(psOpt)), []byte(smbCompose), "example.org", nil); err != nil {
		t.Errorf("router-less template with person_secret / person_id refused: %v", err)
	}
}

func TestZeroRoutersNeedCustom(t *testing.T) {
	for _, method := range []string{"forward-auth", "header-auth", "native-oidc", "mtls", "public"} {
		m := strings.Replace(smbHead, "method: custom", "method: "+method, 1)
		_, err := build("files", "src", "", []byte(m), []byte(smbCompose), "example.org", nil)
		if err == nil || !strings.Contains(err.Error(), "auth.method "+method+" needs at least one HTTP router") {
			t.Errorf("%s with zero routers: %v", method, err)
		}
	}
}

func TestRouterless(t *testing.T) {
	routed, err := build("files", "src", "", []byte(smbHead), []byte(smbRouted), "example.org", nil)
	if err != nil {
		t.Fatal(err)
	}
	if routed.Manifest.Routerless() {
		t.Error("Routerless() = true for custom with a router")
	}
	hdr, err := build("app", "src", "", []byte(hdrHead), []byte(hdrCompose), "example.org", nil)
	if err != nil {
		t.Fatal(err)
	}
	if hdr.Manifest.Routerless() {
		t.Error("Routerless() = true for header-auth")
	}
	// A manifest that wasn't discovered is never router-less (fail closed).
	if (&Manifest{Auth: Auth{Method: "custom"}}).Routerless() {
		t.Error("Routerless() = true for an undiscovered manifest")
	}
}
