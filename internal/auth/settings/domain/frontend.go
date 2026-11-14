package domain

import (
	"errors"
	"net/url"
	"slices"
	"strings"
)

var ErrInvalidFrontend = errors.New("invalid frontend policy")

// A comma-separated canonical list keeps versioned policy equality independent of slice identity.
type FrontendPolicy struct {
	Origins                string `json:"origins"`
	CORSEnabled            bool   `json:"corsEnabled"`
	VerificationURL        string `json:"verificationUrl"`
	ResetURL               string `json:"resetUrl"`
	InvitationURL          string `json:"invitationUrl"`
	EmailChangeURL         string `json:"emailChangeUrl"`
	EmailChangeReportURL   string `json:"emailChangeReportUrl"`
	EmailChangeRecoveryURL string `json:"emailChangeRecoveryUrl"`
}

func (p FrontendPolicy) Validate(allowed []string) error {
	if len(p.Origins) > 4096 {
		return ErrInvalidFrontend
	}
	origins := strings.Split(p.Origins, ",")
	if len(origins) > 32 {
		return ErrInvalidFrontend
	}
	for i, origin := range origins {
		if origin == "" || !slices.Contains(allowed, origin) || slices.Contains(origins[:i], origin) {
			return ErrInvalidFrontend
		}
	}
	for i, address := range []string{p.VerificationURL, p.ResetURL, p.InvitationURL, p.EmailChangeURL, p.EmailChangeReportURL, p.EmailChangeRecoveryURL} {
		if i >= 2 && address == "" {
			continue
		}
		if !trustedActionURL(address, allowed) {
			return ErrInvalidFrontend
		}
	}
	if (p.EmailChangeURL == "" || p.EmailChangeReportURL == "" || p.EmailChangeRecoveryURL == "") &&
		(p.EmailChangeURL != "" || p.EmailChangeReportURL != "" || p.EmailChangeRecoveryURL != "") {
		return ErrInvalidFrontend
	}
	return nil
}

func trustedActionURL(address string, allowed []string) bool {
	u, err := url.Parse(address)
	return err == nil && len(address) <= 2048 && u.Scheme == "https" && u.Hostname() != "" &&
		u.User == nil && u.Opaque == "" && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" &&
		slices.Contains(allowed, u.Scheme+"://"+u.Host)
}
