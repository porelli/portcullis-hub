package httpapi

import (
	"context"

	"github.com/portcullis/hub/internal/directory"
)

// The mail tool (contract §15.10, §19.9): mail_status only. No tool
// creates, lists or revokes a mail password, ever; every other mail
// route is the admin UI's (mcp_parity_test.go mailNoToolRoutes).
func (s *Server) registerMailTools() {
	s.registerTool(admin("mail_status", "The mail server's status: whether mail is on, whether mailctl answers, the certificate, DKIM keys, MTA-STS and DMARC per domain, the queue, the client-address mode, the last restore and timer run, the parked former accounts, and each domain's mail state. No credentials.",
		ClassRead, "GET /api/mail/status", "", func(ctx context.Context, _ directory.Actor, _ noArgs) (any, error) {
			return s.Hub.MailStatus(ctx), nil
		}))
}
