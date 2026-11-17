package directory_test

import (
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/directory"
)

// A new username equal to a shared SSH account of a grant is refused
// (409), directly and through the CSV import (contract §18.12).
func TestCreateUserRefusesSharedSSHAccountName(t *testing.T) {
	e, _ := evalEnv(t)
	e.svc.SSHSharedAccount = func(name string) bool { return name == "deploy" }
	_, err := e.svc.CreateUser(ctx, asRoot, directory.CreateRequest{Username: "deploy", Email: "deploy@example.org"})
	wantStatus(t, "CreateUser deploy", err, 409)
	if err == nil || !strings.Contains(err.Error(), "deploy is a shared SSH account name; pick another username") {
		t.Errorf("error %v", err)
	}
	if e.ll.HasUser("deploy") {
		t.Fatal("account created")
	}
	req := directory.ApplyRequest{Rows: []directory.ApplyRow{{User: "deploy", Create: true, Email: "deploy@example.org"}}}
	if res, err := e.svc.ImportApply(ctx, asRoot, req); err != nil || res.Rows[0].OK || e.ll.HasUser("deploy") {
		t.Fatalf("ImportApply = %+v %v", res, err)
	}
	if _, err := e.svc.CreateUser(ctx, asRoot, directory.CreateRequest{Username: "zed", Email: "zed@example.org"}); err != nil {
		t.Errorf("an unrelated username refused: %v", err)
	}
}
