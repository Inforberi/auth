package httpx

import (
	"net"
	"net/http"
)

func UserAgent(r *http.Request) string {
	return r.UserAgent()
}

func IP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}

	return r.RemoteAddr
}
