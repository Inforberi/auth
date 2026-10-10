package httpx

import (
	"context"
	"net"
	"net/http"
)

type clientIPKey struct{}

func WithClientIP(r *http.Request, ip string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), clientIPKey{}, ip))
}

func UserAgent(r *http.Request) string {
	return r.UserAgent()
}

func IP(r *http.Request) string {
	if ip, ok := r.Context().Value(clientIPKey{}).(string); ok {
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}

	return r.RemoteAddr
}
