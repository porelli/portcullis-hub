package hub

import (
	"context"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/doctor"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/state"
)

// TestInstanceViewServerStates (contract §11.2): server, move and
// moved_from in the view; moving, orphaned and unreachable derived with
// their precedence (deleting first).
func TestInstanceViewServerStates(t *testing.T) {
	p := newPlacedFixture(t)
	placedEnabled(t, p, "plainapp")
	view := func() InstanceView {
		v, ok := p.h.InstanceView("plainapp")
		if !ok {
			t.Fatal("no view")
		}
		return v
	}
	if v := view(); v.Server != "nas" || v.State != StateEnabled || v.Move != nil {
		t.Fatalf("placed %+v", v)
	}
	set := func(fn func(*state.Instance), srv string) {
		p.h.mu.Lock()
		in := p.h.st.Instances["plainapp"]
		fn(&in)
		p.h.st.Instances["plainapp"] = in
		if srv != "" {
			s := p.h.st.Servers["nas"]
			s.State = srv
			p.h.st.Servers["nas"] = s
		}
		p.h.mu.Unlock()
	}
	set(func(in *state.Instance) {}, ServerOffline)
	if v := view(); v.State != StateUnreachable {
		t.Errorf("offline server: %s", v.State)
	}
	set(func(in *state.Instance) {}, ServerRevoked)
	if v := view(); v.State != StateOrphaned {
		t.Errorf("revoked server: %s", v.State)
	}
	at := time.Now().UTC()
	set(func(in *state.Instance) {
		in.State, in.Move = state.InstanceMoving, &state.Move{From: "nas", To: "", Phase: MoveRestore, StartedAt: at}
		in.MovedFrom = &state.MovedFrom{Server: "", At: at, Volumes: []string{"portcullis-plainapp_data"}}
	}, "")
	v := view()
	if v.State != StateMoving || v.Move == nil || v.Move.Phase != MoveRestore || v.MovedFrom == nil || v.MovedFrom.Server != "" {
		t.Errorf("moving %+v", v)
	}
	set(func(in *state.Instance) { in.State = state.InstanceDeleting }, "")
	if v := view(); v.State != StateDeleting {
		t.Errorf("deleting first: %s", v.State)
	}
}

// TestServerSettingsHub: name, Local networks and schedule stored and
// audited; the primary takes the schedule only; an empty fresh proof is
// refused before any exchange.
func TestServerSettingsHub(t *testing.T) {
	p := newPlacedFixture(t)
	name, nets := "Attic", []string{"192.168.7.0/24"}
	sch := state.BackupSchedule{Mode: "weekly", Hour: 5, Weekday: 2}
	if err := p.h.SetServerSettings(context.Background(), admin, "nas", ServerSettings{Name: &name, LocalNetworks: &nets, BackupSchedule: &sch}); err != nil {
		t.Fatal(err)
	}
	d, err := p.h.ServerDetailOf(context.Background(), "nas")
	if err != nil || d.Name != "Attic" || d.LocalNetworksDefault || len(d.LocalNetworks) != 1 || d.BackupSchedule != sch {
		t.Fatalf("%+v %v", d, err)
	}
	if err := p.h.SetServerSettings(context.Background(), admin, "nas", ServerSettings{LocalNetworksDefault: true}); err != nil {
		t.Fatal(err)
	}
	if d, _ := p.h.ServerDetailOf(context.Background(), "nas"); !d.LocalNetworksDefault {
		t.Errorf("defaults %+v", d)
	}
	daily := state.BackupSchedule{Mode: "daily", Hour: 1}
	if err := p.h.SetServerSettings(context.Background(), admin, "primary", ServerSettings{BackupSchedule: &daily}); err != nil {
		t.Fatal(err)
	}
	if err := p.h.SetServerSettings(context.Background(), admin, "primary", ServerSettings{Name: &name}); errStatus(err) != 400 {
		t.Errorf("primary name: %v", err)
	}
	if err := p.h.CheckAdminFresh(context.Background(), admin, "server.add", "nas", freshauth.Proof{}); errStatus(err) != 403 {
		t.Errorf("empty proof: %v", err)
	}
}

// TestServerDoctorInputs (Task 13): a placed instance without a backup,
// an orphan and an old move leftover reach the doctor; the leftover's
// one-click fix previews its volumes, needs the typed id and removes
// them.
func TestServerDoctorInputs(t *testing.T) {
	p := newPlacedFixture(t)
	placedEnabled(t, p, "plainapp")
	p.h.mu.Lock()
	in := p.h.st.Instances["plainapp"]
	in.MovedFrom = &state.MovedFrom{Server: "", At: time.Now().Add(-8 * 24 * time.Hour), Volumes: []string{"portcullis-plainapp_data"}}
	p.h.st.Instances["plainapp"] = in
	p.h.st.Instances["gone"] = state.Instance{Template: "plainapp", Server: "old", State: state.InstanceOrphaned}
	p.h.mu.Unlock()
	p.h.SetPeople(newFakePeople("erin"))
	r, err := p.h.Doctor(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	byKind := map[string][]doctor.Finding{}
	for _, f := range r.Findings {
		byKind[f.Kind] = append(byKind[f.Kind], f)
	}
	if len(byKind[doctor.KindServerNoRecentBackup]) != 1 || len(byKind[doctor.KindInstanceOrphaned]) != 1 {
		t.Errorf("findings %v", byKind)
	}
	lf := byKind[doctor.KindServerMoveLeftover]
	if len(lf) != 1 {
		t.Fatalf("leftover %v", lf)
	}
	plan, err := p.h.PreviewFix(context.Background(), lf[0].FP, nil)
	if err != nil || len(plan.Lines) != 1 || plan.Lines[0] != "remove portcullis-plainapp_data on the primary" || !plan.TouchesData {
		t.Fatalf("plan %+v %v", plan, err)
	}
	if _, err := p.h.ApplyFix(context.Background(), lf[0].FP, map[string]string{"confirm": "nope"}, plan.Hash, admin); errStatus(err) != 400 {
		t.Errorf("mistyped: %v", err)
	}
	op, err := p.h.ApplyFix(context.Background(), lf[0].FP, map[string]string{"confirm": "plainapp"}, plan.Hash, admin)
	if err != nil {
		t.Fatal(err)
	}
	if rec := waitOp(t, p.h, "plainapp", op.OpID); !rec.OK {
		t.Fatalf("op %+v", rec)
	}
	if in := p.instance("plainapp"); in.MovedFrom != nil {
		t.Errorf("leftover kept %+v", in.MovedFrom)
	}
}
