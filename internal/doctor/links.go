package doctor

import (
	"regexp"
	"strings"
)

// Links (contract §14.5 "Links"): where a finding's fix lives on the Hub.
// A check may set Finding.Link; otherwise defaultLink gives the kind its
// page. Run then builds Link.Hash, the route, from validated parts only
// (the instance id, the option key, and the fixed tab and page names of
// this file), never from a finding's text, and drops a link whose parts
// don't validate.

// The instance page's tabs a link may open (web/index.html PAGE_TABS).
var linkTabs = map[string]bool{
	"overview": true, "settings": true, "groups": true, "filesharing": true, "logs": true, "usage": true,
	"backups": true, "ai": true, "vpn": true, "mail": true, "expert": true,
}

// The Hub pages off the instance pages a link may open (index.html ROUTES).
const (
	PageSettingsSignIn  = "settings/signin"
	PageSettingsNetwork = "settings/network"
	PageSettingsStorage = "settings/storage"
	PageSettingsMail    = "settings/mail"
	PageSettingsAI      = "settings/ai"
	PageSettingsServers = "settings/servers"
	PageSettingsSSH     = "settings/ssh"
	PageSettingsSources = "settings/sources"
	PageAccessSSH       = "access/ssh"
	PageAccessSSHHosts  = "access/ssh/hosts"
	PageAccessSSHGroups = "access/ssh/hostgroups"
	PageAccessSSHGrants = "access/ssh/grants"
	PageAccessSSHCerts  = "access/ssh/certs"
	PageAccessVPN       = "access/vpn"
	PageUsage           = "usage"
	PageUsageStorage    = "usage/storage"
)

var linkPages = map[string]bool{
	PageSettingsSignIn: true, PageSettingsNetwork: true, PageSettingsStorage: true, PageSettingsMail: true,
	PageSettingsAI: true, PageSettingsServers: true, PageSettingsSSH: true, PageSettingsSources: true,
	PageAccessSSH: true, PageAccessSSHHosts: true, PageAccessSSHGroups: true, PageAccessSSHGrants: true,
	PageAccessSSHCerts: true, PageAccessVPN: true, PageUsage: true, PageUsageStorage: true,
}

var (
	linkInstanceRe = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	linkOptionRe   = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
)

// Route is l's Hub hash route, or "" when a part doesn't validate (the
// link is then dropped).
func (l Link) Route() string {
	if l.Page != "" {
		if l.Instance != "" || l.Option != "" || l.Tab != "" || !linkPages[l.Page] {
			return ""
		}
		return "#" + l.Page
	}
	if len(l.Instance) > 64 || !linkInstanceRe.MatchString(l.Instance) {
		return ""
	}
	base := "#apps/" + l.Instance
	switch {
	case l.Option != "":
		if (l.Tab != "" && l.Tab != "settings") || !linkOptionRe.MatchString(l.Option) {
			return ""
		}
		return base + "/settings/" + l.Option
	case l.Tab == "" || l.Tab == "overview":
		return base
	case linkTabs[l.Tab]:
		return base + "/" + l.Tab
	}
	return ""
}

// finishLink sets f.Link from the kind's table when the check set none,
// then its Hash; a link that doesn't validate is dropped.
func finishLink(f *Finding) {
	if f.Link == nil {
		f.Link = defaultLink(f)
	}
	if f.Link == nil {
		return
	}
	l := *f.Link
	l.Hash = l.Route()
	if l.Hash == "" {
		f.Link = nil
		return
	}
	f.Link = &l
}

// oneInstance is f's instance when it names exactly one.
func oneInstance(f *Finding) string {
	if len(f.Instances) == 1 {
		return f.Instances[0]
	}
	return ""
}

func page(p string) *Link { return &Link{Page: p} }

// tabOr: the one instance's tab, else the page p ("" = no link).
func tabOr(f *Finding, tab, p string) *Link {
	if id := oneInstance(f); id != "" {
		return &Link{Instance: id, Tab: tab}
	}
	if p == "" {
		return nil
	}
	return page(p)
}

// The kinds by the page their fix lives on.
var (
	storageKinds = set(KindSharedPath, KindPathOutsideRoots, KindPrimaryGIDConflict, KindMustOwnConflict, KindExclusive,
		KindGIDCollision, KindFolderChanged, KindFolderReachAbove, KindFolderOwner, KindFilesystem, KindFreeSpace,
		KindNoACL, KindSkippedEntries, KindScanFailed, KindUnmappedOwner)
	fileSharingKinds = set(KindCredentialWithoutAccess, KindFormerAccountFolder, KindPersonTreeOwner, KindUnverifiableAccount,
		KindServedToNobody, KindNameRefused, KindOwnerUnwritable)
	serverKinds = set(KindServerOffline, KindServerCertExpiring, KindServerAgentIncompatible, KindServerAgentOutdated,
		KindServerDiskLow, KindServerNoRecentBackup, KindLinkSubnetOverlap, KindServerSecretsNotRotated)
	serverInstanceKinds = set(KindInstanceQuarantined, KindMoveStuck, KindServerMoveLeftover,
		KindCopyNotRemoved, KindPlacementInvalid, KindInstanceOrphaned)
	vpnProviderKinds = set(KindVPNProviderStale, KindVPNProviderInvalid, KindVPNViaDead, KindVPNStaticMapping, KindVPNGatewayPrivileged)
	vpnDeviceKinds   = set(KindVPNNoAdminDevice, KindVPNDeviceStale, KindVPNExpiring)
	sshHostKinds     = set(KindSSHHostStale, KindSSHHostDrift, KindSSHHostAccountConflict, KindSSHHostAccountMissing,
		KindSSHHostAccountInvalid, KindSSHHostCeiling, KindSSHHostAuthorizedKeys, KindSSHHostCertExpiring, KindSSHHostBundleTooLarge)
	mailProviderKinds = set(KindMailProviderRefused, KindMailProviderUnreach, KindMailProviderCheck, KindMailVoidPending)
)

func set(ks ...string) map[string]bool {
	m := make(map[string]bool, len(ks))
	for _, k := range ks {
		m[k] = true
	}
	return m
}

// defaultLink is the kind's page (contract §14.5 "Links"), nil for a kind
// whose fix lives on no Hub page.
func defaultLink(f *Finding) *Link {
	k := f.Kind
	switch {
	case mailProviderKinds[k]:
		// The wired provider's Mail tab (the check names it), else
		// Settings → Mail.
		return tabOr(f, "mail", PageSettingsMail)
	case strings.HasPrefix(k, "mail_"):
		return page(PageSettingsMail)
	case strings.HasPrefix(k, "dns_"), strings.HasPrefix(k, "dnssec_"), k == KindLocalNetworksEmpty:
		return page(PageSettingsNetwork)
	case vpnDeviceKinds[k]:
		return page(PageAccessVPN)
	case vpnProviderKinds[k]:
		return tabOr(f, "vpn", PageSettingsNetwork)
	case strings.HasPrefix(k, "vpn_"):
		return page(PageSettingsNetwork)
	case storageKinds[k]:
		return page(PageSettingsStorage)
	case fileSharingKinds[k]:
		return tabOr(f, "filesharing", "")
	case serverInstanceKinds[k]:
		return tabOr(f, "overview", PageSettingsServers)
	case serverKinds[k]:
		return page(PageSettingsServers)
	case k == KindSSHCAMissing, k == KindSSHCLIClientConflict:
		return page(PageSettingsSSH)
	case sshHostKinds[k]:
		return page(PageAccessSSHHosts)
	case k == KindSSHHostGroupUnused:
		return page(PageAccessSSHGroups)
	case k == KindSSHPrivilegedGrant:
		return page(PageAccessSSHGrants)
	case k == KindSSHBreakglassUsed, k == KindSSHBreakglassCert, k == KindSSHRevocationIncomplete:
		return page(PageAccessSSHCerts)
	case k == KindSignInTOTPPolicyDrift, k == KindSignInLoginErrorsCapped, k == KindSignInFIDOUnavailable:
		return page(PageSettingsSignIn)
	case strings.HasPrefix(k, "ai_"):
		// The checks set the AI tab themselves; this is the fallback.
		return tabOr(f, TabAI, "")
	case k == KindMemoryNearLimit, k == KindOOMKilled, k == KindPidsNearLimit:
		return tabOr(f, TabUsage, PageUsage)
	case k == KindPersonOption:
		return tabOr(f, "settings", "")
	case k == KindDiskNearlyFull, k == KindStorageMeasurePartial:
		return page(PageUsageStorage)
	case k == KindUsageNotMeasured:
		return page(PageUsage)
	case k == KindCustomOverrideMount:
		return tabOr(f, "expert", "")
	case k == KindLANOnlyExposed, k == KindHostNetwork:
		return tabOr(f, "settings", "")
	case k == KindReloadDegraded, k == KindUndeclaredTemplate:
		return tabOr(f, "overview", "")
	}
	return nil
}

// LinkHashPattern is every hash Route can build, and nothing else: the
// Hub UI (web/doctor.js LINK_RE, the same text; TestDoctorLinkPattern)
// shows a finding's link only when its hash matches it.
const LinkHashPattern = `^#(?:apps/[a-z0-9]+(?:-[a-z0-9]+)*(?:/(?:overview|settings|groups|filesharing|logs|usage|backups|ai|vpn|mail|expert)|/settings/[A-Za-z0-9_.-]{1,128})?|settings/(?:signin|network|storage|mail|ai|servers|ssh|sources)|access/(?:ssh(?:/(?:hosts|hostgroups|grants|certs))?|vpn)|usage(?:/storage)?)$`
