package telegram

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"time"
)

type boundedTransport struct {
	transport *http.Transport
	client    *http.Client
}

func newHTTPClient() (*boundedTransport, *http.Client) {
	t := &boundedTransport{transport: &http.Transport{
		DialContext:         (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 5 * time.Second,
		MaxResponseHeaderBytes: 16384, MaxConnsPerHost: 16, MaxIdleConnsPerHost: 8,
		MaxIdleConns: 16, IdleConnTimeout: 90 * time.Second, ForceAttemptHTTP2: true,
	}}
	t.client = &http.Client{
		Transport: t, Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("provider redirects forbidden") },
	}
	return t, t.client
}

func (t *boundedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" || r.URL.Host != "oauth.telegram.org" || r.URL.User != nil ||
		(r.URL.Path != "/token" && r.URL.Path != "/.well-known/jwks.json") {
		return nil, errors.New("untrusted Telegram endpoint")
	}
	response, err := t.transport.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	response.Body = &boundedBody{Reader: io.LimitReader(response.Body, 65536), Closer: response.Body}
	return response, nil
}

type boundedBody struct {
	io.Reader
	io.Closer
}
