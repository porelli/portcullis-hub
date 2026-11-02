package settings

import (
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	_ "time/tzdata" // iana_tz must not depend on the image's zoneinfo

	"github.com/robfig/cron/v3"
	"golang.org/x/mod/semver"
	"golang.org/x/text/language"

	"github.com/portcullis/hub/internal/lldap"
	"github.com/portcullis/hub/internal/templates"
)

// formats are the string formats of §13.2: each returns why s isn't one.
var formats = map[string]func(s string) error{
	"hostname": func(s string) error {
		if !templates.ValidHostname(s) {
			return fmt.Errorf("want a lowercase DNS name such as app.example.com")
		}
		return nil
	},
	"ip": func(s string) error {
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" {
			return fmt.Errorf("want an IPv4 or IPv6 address")
		}
		return nil
	},
	"cidr": func(s string) error {
		p, err := netip.ParsePrefix(s)
		if err != nil || p.Addr().Zone() != "" {
			return fmt.Errorf("want an address/prefix such as 10.0.0.0/8")
		}
		return nil
	},
	"url": func(s string) error {
		u, err := url.Parse(s)
		if err != nil || u.Scheme == "" || u.Host == "" || u.Opaque != "" {
			return fmt.Errorf("want an absolute URL such as https://host/path")
		}
		return nil
	},
	"email": func(s string) error {
		if !lldap.ValidEmail(s) {
			return fmt.Errorf("want a bare address such as name@example.com")
		}
		return nil
	},
	"iana_tz": func(s string) error {
		if s == "" || s == "Local" {
			return fmt.Errorf("want an IANA time zone such as Europe/Rome")
		}
		if _, err := time.LoadLocation(s); err != nil {
			return fmt.Errorf("want an IANA time zone such as Europe/Rome")
		}
		return nil
	},
	"locale": func(s string) error {
		t, err := language.Parse(s)
		if err != nil || t.String() != s {
			return fmt.Errorf("want a BCP 47 tag in canonical form such as it-IT")
		}
		return nil
	},
	"cron": func(s string) error {
		// Time zone prefixes and @every are robfig extensions, not cron.
		if strings.HasPrefix(s, "TZ=") || strings.HasPrefix(s, "CRON_TZ=") || strings.HasPrefix(s, "@every") {
			return fmt.Errorf("want a five-field cron expression such as */5 * * * *")
		}
		if _, err := cron.ParseStandard(s); err != nil {
			return fmt.Errorf("want a five-field cron expression such as */5 * * * *")
		}
		return nil
	},
	"semver": func(s string) error {
		v := "v" + s
		// x/mod accepts the shorthand v1.2: require MAJOR.MINOR.PATCH.
		if !semver.IsValid(v) || strings.TrimSuffix(v, semver.Build(v)) != semver.Canonical(v) {
			return fmt.Errorf("want MAJOR.MINOR.PATCH such as 1.2.3")
		}
		return nil
	},
	"hex": func(s string) error {
		if !hexRe.MatchString(s) {
			return fmt.Errorf("want hexadecimal digits")
		}
		return nil
	},
}

var hexRe = regexp.MustCompile(`^[0-9a-fA-F]+$`)

func formatNames() string {
	var n []string
	for k := range formats {
		n = append(n, k)
	}
	sort.Strings(n)
	return strings.Join(n, ", ")
}
