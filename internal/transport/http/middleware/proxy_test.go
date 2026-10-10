package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

func TestTrustedProxyIP(t *testing.T) {
	for _, tc := range []struct{ peer, header, want string }{
		{"198.51.100.1:1234", "192.0.2.7", "198.51.100.1"},
		{"10.0.0.1:1234", "192.0.2.7", "192.0.2.7"},
		{"10.0.0.1:1234", "203.0.113.9, 192.0.2.7", "192.0.2.7"},
		{"10.0.0.1:1234", "192.0.2.7, 10.0.0.2", "192.0.2.7"},
		{"10.0.0.1:1234", "192.0.2.7, invalid", "10.0.0.1"},
		{"[::ffff:10.0.0.1]:1234", "192.0.2.7", "192.0.2.7"},
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = tc.peer
		r.Header.Set("X-Forwarded-For", tc.header)
		ClientIP(ProxyConfig{TrustedCIDRs: []string{"10.0.0.0/8"}})(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			if got := httpx.IP(r); got != tc.want {
				t.Errorf("%s: got %s, want %s", tc.header, got, tc.want)
			}
		})).ServeHTTP(httptest.NewRecorder(), r)
	}
	if (ProxyConfig{TrustedCIDRs: []string{"not-cidr"}}).Validate() == nil {
		t.Fatal("invalid CIDR accepted")
	}
}
