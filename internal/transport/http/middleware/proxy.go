package middleware

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type ProxyConfig struct {
	TrustedCIDRs []string `env:"HTTP_TRUSTED_PROXY_CIDRS" env-separator:","`
}

func (c ProxyConfig) Validate() error {
	for _, cidr := range c.TrustedCIDRs {
		if _, err := netip.ParsePrefix(strings.TrimSpace(cidr)); err != nil {
			return fmt.Errorf("invalid trusted proxy CIDR")
		}
	}
	return nil
}

func ClientIP(cfg ProxyConfig) func(http.Handler) http.Handler {
	var trusted []netip.Prefix
	for _, cidr := range cfg.TrustedCIDRs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(cidr))
		if err == nil {
			trusted = append(trusted, prefix)
		}
	}
	isTrusted := func(ip netip.Addr) bool {
		for _, prefix := range trusted {
			if prefix.Contains(ip) {
				return true
			}
		}
		return false
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				host = r.RemoteAddr
			}
			peer, err := netip.ParseAddr(host)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}
			ip := peer.Unmap()
			forwarded := r.Header.Get("X-Forwarded-For")
			if isTrusted(ip) && len(forwarded) <= 2048 {
				chain := strings.Split(forwarded, ",")
				for i := len(chain) - 1; i >= 0 && isTrusted(ip); i-- {
					candidate, err := netip.ParseAddr(strings.TrimSpace(chain[i]))
					if err != nil {
						ip = peer.Unmap()
						break
					}
					ip = candidate.Unmap()
				}
			}
			next.ServeHTTP(w, httpx.WithClientIP(r, ip.String()))
		})
	}
}
