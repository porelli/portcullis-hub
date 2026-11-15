package agentapi

// Body kinds of a route's request and response.
type Body string

const (
	BodyNone   Body = "none"
	BodyJSON   Body = "json"   // one JSON document (≤ MaxJSON; Info ≤ MaxInfo)
	BodyNDJSON Body = "ndjson" // JSON lines (≤ MaxLine each)
	BodyText   Body = "text"   // raw bytes (logs, ≤ MaxLogs)
	BodyTar    Body = "tar"    // a tar stream
)

// Route is one agent API route: the HTTP method, the http.ServeMux
// pattern path ({id} an instance id, {cid} a container id, {exec} an exec
// id, {h} a helper id, {name} a volume or data file name, {op} an op id) and the bodies. Every route but GET /v1/metrics needs
// the hub.control client certificate; GET /v1/metrics also takes
// link.control. The enrol routes exist in enrolling mode only.
type Route struct {
	Method, Path      string
	Request, Response Body
}

// Pattern is r as a Go 1.22 http.ServeMux pattern.
func (r Route) Pattern() string { return r.Method + " " + r.Path }

// Routes maps every runtime.Instances method but Kind and Env (the
// agent backend answers those itself: Kind from the last Info, Env its
// own compose environment) to the routes it calls, in order (contract
// §17.4; pre-flight P8; TestRoutesCoverInstances). The helper methods
// share POST /v1/helpers (HelperSpec → HelperCreated) and
// /v1/helpers/{h}/archive.
var Routes = map[string][]Route{
	"Info": {{"GET", Prefix + "/info", BodyNone, BodyJSON}},

	"Create":     {{"POST", Prefix + "/projects/{id}/create", BodyNone, BodyNone}},
	"Up":         {{"POST", Prefix + "/projects/{id}/up", BodyNone, BodyNDJSON}},
	"Down":       {{"POST", Prefix + "/projects/{id}/down", BodyNone, BodyNone}},
	"DownByName": {{"POST", Prefix + "/projects/{id}/down-by-name", BodyNone, BodyNone}},
	"Pull":       {{"POST", Prefix + "/images/pull", BodyJSON, BodyNDJSON}},

	"List":        {{"GET", Prefix + "/containers", BodyNone, BodyJSON}},
	"Inspect":     {{"GET", Prefix + "/containers/{cid}", BodyNone, BodyJSON}},
	"Logs":        {{"GET", Prefix + "/containers/{cid}/logs", BodyNone, BodyText}},
	"Exec":        {{"POST", Prefix + "/containers/{cid}/exec", BodyJSON, BodyJSON}},
	"ExecSplit":   {{"POST", Prefix + "/containers/{cid}/exec-split", BodyJSON, BodyJSON}},
	"ExecRunning": {{"GET", Prefix + "/execs/{exec}", BodyNone, BodyJSON}},
	"Signal":      {{"POST", Prefix + "/containers/{cid}/kill", BodyJSON, BodyNone}},
	"State":       {{"GET", Prefix + "/containers/{cid}/state", BodyNone, BodyJSON}},
	"Events":      {{"GET", Prefix + "/events", BodyNone, BodyNDJSON}},

	"ListVolumes":   {{"GET", Prefix + "/volumes", BodyNone, BodyJSON}},
	"InspectVolume": {{"GET", Prefix + "/volumes/{name}", BodyNone, BodyJSON}},
	"CreateVolume":  {{"POST", Prefix + "/volumes", BodyJSON, BodyNone}},
	"RemoveVolume":  {{"DELETE", Prefix + "/volumes/{name}", BodyNone, BodyNone}},
	"VolumeOut":     {helperCreate, {"GET", Prefix + "/helpers/{h}/archive", BodyNone, BodyTar}, helperDelete},
	"VolumeIn":      {helperCreate, {"PUT", Prefix + "/helpers/{h}/archive", BodyTar, BodyNone}, helperDelete},
	"RemoveHelper":  {helperDelete},

	"RunFixer": {helperCreate, {"PUT", Prefix + "/helpers/{h}/archive", BodyTar, BodyNone},
		{"POST", Prefix + "/helpers/{h}/run", BodyNone, BodyJSON}, {"GET", Prefix + "/helpers/{h}/archive", BodyNone, BodyTar}, helperDelete},
	"EnsureImage": {{"POST", Prefix + "/images/ensure", BodyJSON, BodyNone}},
}

var (
	helperCreate = Route{"POST", Prefix + "/helpers", BodyJSON, BodyJSON}
	helperDelete = Route{"DELETE", Prefix + "/helpers/{h}", BodyNone, BodyNone}
)

// Logs query parameters (GET /v1/containers/{cid}/logs?tail=&ts=1).
const (
	QueryTail = "tail"
	QueryTS   = "ts"
)

// ExtraRoutes are the routes no runtime.Instances method maps to: the
// bundle and data-file deliveries, the project's removal, Stop, metrics, identity and
// enrolment, the network parameters and leave.
var ExtraRoutes = map[string]Route{
	"Bundle":        {"PUT", Prefix + "/projects/{id}/bundle", BodyTar, BodyNone},
	"RemoveProject": {"DELETE", Prefix + "/projects/{id}", BodyNone, BodyNone},
	"AppFile":       {"PUT", Prefix + "/projects/{id}/appfiles/{name}", BodyTar, BodyNone},
	"StopOp":        {"DELETE", Prefix + "/ops/{op}", BodyNone, BodyNone},
	"Metrics":       {"GET", Prefix + "/metrics", BodyNone, BodyText},
	"IdentityCSR":   {"POST", Prefix + "/identity/csr", BodyNone, BodyJSON},
	"IdentityCert":  {"PUT", Prefix + "/identity/cert", BodyJSON, BodyNone},
	"IdentityWG":    {"PUT", Prefix + "/identity/wg", BodyJSON, BodyNone},
	"Network":       {"PUT", Prefix + "/network", BodyJSON, BodyNone},
	"Leave":         {"POST", Prefix + "/leave", BodyNone, BodyNone},
	"EnrolNonce":    {"GET", Prefix + "/enrol/nonce", BodyNone, BodyJSON},
	"Enrol":         {"POST", Prefix + "/enrol", BodyJSON, BodyJSON},
}
