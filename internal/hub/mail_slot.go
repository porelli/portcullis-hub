package hub

import (
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/portcullis/hub/internal/mailprovider"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// The mail slot (contract §19.1): core's infrastructure, the Hub's
// driver. At most one instance of a template with a mail: block is wired;
// only it gets the slot's powers, through the override (mail_override.go).

const (
	// MailProviderGID is the contract's mail-provider group
	// (CT_GID_MAIL_PROVIDER): the certificate, the gate and the secret.
	MailProviderGID = 2000
	// mailAPINetwork, mailMetricsNetwork: core's networks the override
	// attaches the provider to.
	mailAPINetwork     = "portcullis-mail-api"
	mailMetricsNetwork = "portcullis-metrics-mail"
	// The provider's aliases on them.
	mailAPIAlias           = "mail-api"
	mailMetricsAlias       = "mail-provider-metrics"
	mailServerMetricsAlias = "mail-provider-server-metrics"
	// mailTLSVolumeKey / mailTLSVolume: the reserved override key and
	// core's volume (portcullis_mail_tls) holding the mail certificate.
	mailTLSVolumeKey = "portcullis-mail-tls"
	mailTLSVolume    = "portcullis_mail_tls"
	// The provider's mount points (contract §19.4).
	MailSlotMount = "/run/portcullis/mail/slot"
	MailTLSMount  = "/run/portcullis/mail/tls"
	// mailSlotSub is the gate's directory under hub_secrets/<instance>/.
	mailSlotSub = "_mail"
	// MailWellknownRouter is the Hub's well-known router and service.
	MailWellknownRouter = "portcullis-mail-wellknown"
	// The provider's environment (contract §19.4).
	VarMailSlotDir              = "PORTCULLIS_MAIL_SLOT_DIR"
	VarMailTLSDir               = "PORTCULLIS_MAIL_TLS_DIR"
	VarMailWellknownEntrypoints = "PORTCULLIS_MAIL_WELLKNOWN_ENTRYPOINTS"
	VarMailVoidSession          = "PORTCULLIS_MAIL_VOID_SESSION"
	mailProxyNetwork            = "portcullis-proxy"
	mailWellknownMiddlewares    = "rate-limit@file,security-headers@file"
	mailWellknownTLSOptions     = "public@file"
	mailGateFileVoidSession     = "void-session"
)

// mailMode is how the override renders an instance of a mail template.
type mailMode int

const (
	// mailUnwired: an ordinary app (no ports, attachment, mount, router).
	mailUnwired mailMode = iota
	// mailVoid: the API attachment, the mounts and the env with the void
	// session; every template network internal; no ports, router or
	// metrics.
	mailVoid
	// mailNormal: everything (contract §19.1).
	mailNormal
)

func (m mailMode) String() string {
	switch m {
	case mailVoid:
		return "void"
	case mailNormal:
		return "normal"
	}
	return "unwired"
}

// mailProviderLocked is the wired provider (nil: nothing wired). Caller
// must hold mu.
func (h *Hub) mailProviderLocked() *state.MailProvider { return h.st.Mail.Provider }

// mailModeLocked is instance id's mode (P4): void while a void is owed,
// normal otherwise; unwired unless it is the wired instance. A hold
// changes no mode (Ruling R-HH1): the running, confirmed containers keep
// serving and keep taking revocations; it only refuses every up of the
// changed tree (mailHoldGateLocked, R-HH3). Caller must hold mu.
func (h *Hub) mailModeLocked(id string) mailMode {
	p := h.st.Mail.Provider
	if p == nil || p.Instance != id {
		return mailUnwired
	}
	// A closed or invalid slot (PORTCULLIS_MAIL off or a bad key) never
	// renders the public listeners (L18): void mode, fail closed.
	if h.st.Mail.VoidOwed != nil || !h.mailOn() {
		return mailVoid
	}
	return mailNormal
}

// mailModeTextLocked is the mode as reported (M2): "stopped" for a held
// provider the Hub stopped, else the mode. Caller must hold mu.
func (h *Hub) mailModeTextLocked(id string) string {
	m := h.mailModeLocked(id)
	if hd := h.st.Mail.Held; m != mailUnwired && hd != nil && hd.Stopped != nil {
		return "stopped"
	}
	return m.String()
}

// mailWiredLocked is the wired instance's view and its mail: block (nil
// when nothing is wired, the instance is gone or its template has no
// block any more). Caller must hold mu.
func (h *Hub) mailWiredLocked() (*templates.Template, *templates.Mail) {
	p := h.st.Mail.Provider
	if p == nil {
		return nil, nil
	}
	t := h.findLocked(p.Instance)
	if t == nil || t.Manifest.Mail == nil {
		return nil, nil
	}
	return t, t.Manifest.Mail
}

// mailSlotDirRel is <instance>/_mail under hub_secrets.
func mailSlotDirRel(id string) string { return id + "/" + mailSlotSub }

// mailSlotDir is instance id's gate directory as the Hub sees it ("" =
// no secrets directory).
func (h *Hub) mailSlotDir(id string) string {
	if h.cfg.SecretsDir == "" || !templates.ValidID(id) {
		return ""
	}
	return filepath.Join(h.cfg.SecretsDir, id, mailSlotSub)
}

// checkMailAPIURL refuses a HUB_MAIL_API_URL that isn't http://host[:port]
// ("" = the default from the wired block): the Hub dials only that.
func checkMailAPIURL(raw string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("HUB_MAIL_API_URL %q must be http://<host>[:<port>] (empty: http://mail-api:<api.port>)", raw)
	}
	return nil
}

// mailClients caches the wired provider's client by (URL, secret file).
type mailClients struct {
	mu  sync.Mutex
	key string
	c   *mailprovider.Client
}

// errMailNotWired: no provider is wired (or its template is gone).
var errMailNotWired = errors.New("no mail provider is wired")

// mailProviderAPILocked is the wired provider's client: the test seam
// (SetMailAPI) when set, else a client on HUB_MAIL_API_URL (default
// http://mail-api:<api.port>) with the instance's _mail/api-secret. nil
// when nothing usable is wired. Caller must hold mu (read).
func (h *Hub) mailProviderAPILocked() MailAPI {
	if h.mailAPI != nil {
		return h.mailAPI
	}
	t, m := h.mailWiredLocked()
	if t == nil {
		return nil
	}
	url := h.cfg.MailAPIURL
	if url == "" {
		url = "http://" + mailAPIAlias + ":" + strconv.Itoa(m.API.Port)
	}
	dir := h.mailSlotDir(t.ID)
	if dir == "" {
		return nil
	}
	secret := filepath.Join(dir, "api-secret")
	key := url + "\x00" + secret
	h.mailClients.mu.Lock()
	defer h.mailClients.mu.Unlock()
	if h.mailClients.key != key || h.mailClients.c == nil {
		h.mailClients.key, h.mailClients.c = key, mailprovider.New(url, secret)
	}
	return h.mailClients.c
}

// IsWiredMailProvider: id is the wired mail provider (Ruling R-L23: no
// AI path into its containers).
func (h *Hub) IsWiredMailProvider(id string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	p := h.st.Mail.Provider
	return p != nil && p.Instance == id
}

// IsMailInstance: id is an instance of a mail provider template (a
// mail: block), wired or not (final review M4).
func (h *Hub) IsMailInstance(id string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	t := h.findLocked(id)
	return (t != nil && t.Manifest.Mail != nil) || (h.st.Mail.Provider != nil && h.st.Mail.Provider.Instance == id)
}
