package domain

import (
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	idPattern    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	slugPattern  = regexp.MustCompile(`^[a-z]([a-z0-9-]*[a-z0-9])?$`)
	labelPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)
)

func ValidID(id ID) bool {
	return id != "00000000-0000-0000-0000-000000000000" && idPattern.MatchString(string(id))
}

func ValidSlug(slug string) bool {
	if len(slug) > 63 || !slugPattern.MatchString(slug) {
		return false
	}
	switch slug {
	case "admin", "api", "auth", "console", "platform", "www":
		return false
	}
	return true
}

func NormalizeName(name string) (string, error) {
	if !utf8.ValidString(name) || strings.ContainsFunc(name, unicode.IsControl) {
		return "", ErrInvalidProject
	}
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 200 {
		return "", ErrInvalidProject
	}
	return name, nil
}

// ValidOrigin checks canonical syntax, not registration or control of the domain.
func ValidOrigin(value string) bool {
	if len(value) > 280 {
		return false
	}
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Host == "" ||
		u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.String() != value {
		return false
	}
	host := u.Hostname()
	if !validDNSHost(host) {
		return false
	}
	if u.Host != host {
		port, err := strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 || port == 443 || strconv.Itoa(port) != u.Port() {
			return false
		}
		return u.Host == net.JoinHostPort(host, u.Port())
	}
	return true
}

func validDNSHost(host string) bool {
	if host != strings.ToLower(host) || len(host) > 253 || net.ParseIP(host) != nil {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) > 63 || !labelPattern.MatchString(label) {
			return false
		}
	}
	return true
}
