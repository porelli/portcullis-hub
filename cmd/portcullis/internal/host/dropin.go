package host

import "strings"

// DropIn is /etc/ssh/sshd_config.d/50-portcullis.conf (contract §18.14).
// Spike S3: a Match block ends at the end of its included file on
// OpenSSH 8.2–10.0, so no "Match all" is needed; KbdInteractiveAuthentication
// is always written (8.2 refuses ChallengeResponseAuthentication inside
// Match). origin is "host sync (<domain>, host <id>)" or "host trust
// (<domain>, host group <hg>)".
func DropIn(origin string, hostCert bool) []byte {
	var b strings.Builder
	b.WriteString("# Written by portcullis " + origin + ". Do not edit.\n")
	b.WriteString("TrustedUserCAKeys " + UserCAFile + "\n")
	b.WriteString("AuthorizedPrincipalsFile " + PrincipalsDir + "/%u\n")
	b.WriteString("RevokedKeys " + RevokedKeysFile + "\n")
	if hostCert {
		b.WriteString("HostCertificate " + HostCertFile + "\n")
	}
	b.WriteString("Match Group " + UsersGroup + "\n")
	b.WriteString("    AuthorizedKeysFile none\n")
	b.WriteString("    PasswordAuthentication no\n")
	b.WriteString("    KbdInteractiveAuthentication no\n")
	return []byte(b.String())
}

// SyncOrigin and TrustOrigin are the drop-in's first-line origins.
func SyncOrigin(domain, hostID string) string {
	return "host sync (" + domain + ", host " + hostID + ")"
}

func TrustOrigin(domain, hg string) string {
	return "host trust (" + domain + ", host group " + hg + ")"
}
