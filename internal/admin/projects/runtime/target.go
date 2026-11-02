package runtime

import (
	"crypto/tls"
	"path/filepath"
	"strings"
)

// Target is operational configuration, never a DSN supplied by an API caller.
type Target struct {
	host string
	port uint16
	tls  *tls.Config
}

func NewTarget(host string, port uint16, transport *tls.Config) (Target, error) {
	if host == "" || port == 0 || strings.ContainsAny(host, ", \t\n\r\\?#@\x00") {
		return Target{}, ErrUnavailable
	}
	if strings.HasPrefix(host, "/") {
		if transport != nil || filepath.Clean(host) != host {
			return Target{}, ErrUnavailable
		}
		return Target{host: host, port: port}, nil
	}
	if transport == nil || transport.InsecureSkipVerify || transport.ServerName != host {
		return Target{}, ErrUnavailable
	}
	config := transport.Clone()
	// CertPool.Clone prevents later mutation by the owner of the supplied config.
	if config.RootCAs != nil {
		config.RootCAs = config.RootCAs.Clone()
	}
	config.MinVersion = max(config.MinVersion, tls.VersionTLS12)
	return Target{host: host, port: port, tls: config}, nil
}
