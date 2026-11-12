package signinhistory

import "github.com/portcullis/hub/internal/state"

// OpenedApp is an app opened during an impersonation (contract §8.2
// "Impersonation entries"): its name and whether it keeps its own session
// (a native-OIDC app, which may outlast the end).
type OpenedApp struct {
	Name       string `json:"name"`
	OwnSession bool   `json:"own_session"`
}

// OpenedAppOf converts a stored record's app (state never imports this
// package, F1).
func OpenedAppOf(a state.ImpersonationApp) OpenedApp {
	return OpenedApp{Name: a.Name, OwnSession: a.OwnSession}
}
