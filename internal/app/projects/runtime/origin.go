package runtime

import (
	"errors"
	"net/url"
)

func ValidateProjectEmailOrigin(originURL string, urls ...string) error {
	origin, err := url.Parse(originURL)
	if err != nil || origin.Scheme != "https" || origin.Hostname() == "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" {
		return errors.New("project email requires a trusted HTTPS origin")
	}
	for _, raw := range urls {
		target, err := url.Parse(raw)
		if err != nil || target.Scheme != origin.Scheme || target.Host != origin.Host {
			return errors.New("project email URL must use its trusted origin")
		}
	}
	return nil
}
