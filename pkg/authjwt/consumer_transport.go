package authjwt

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func validEndpoint(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && len(raw) <= 2048 && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.Opaque == "" && !strings.ContainsAny(raw, "\r\n\t ")
}

func consumerTransport(roots *x509.CertPool) *http.Transport {
	if roots != nil {
		roots = roots.Clone()
	}
	return &http.Transport{
		Proxy:               nil,
		DialContext:         (&net.Dialer{Timeout: time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		TLSHandshakeTimeout: time.Second, ResponseHeaderTimeout: 2 * time.Second,
		MaxResponseHeaderBytes: 8192, MaxConnsPerHost: 32, MaxIdleConnsPerHost: 32, MaxIdleConns: 64,
		IdleConnTimeout: 30 * time.Second, DisableCompression: true,
		// HTTP/1 keeps non-replayable POST semantics explicit; no transparent HTTP/2 retry path.
		TLSNextProto: make(map[string]func(string, *tls.Conn) http.RoundTripper),
	}
}

type remoteJSON struct {
	data   []byte
	status int
	header http.Header
}

func (c *Consumer) request(req *http.Request, limit int) (result remoteJSON, resultErr error) {
	resp, err := c.client.Do(req)
	if err != nil {
		return remoteJSON{}, ErrAuthorityUnavailable
	}
	defer func() {
		if resp.Body.Close() != nil {
			result, resultErr = remoteJSON{}, ErrAuthorityUnavailable
		}
	}()
	result = remoteJSON{status: resp.StatusCode, header: resp.Header}
	if resp.StatusCode != http.StatusOK {
		return result, nil
	}
	media, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || (media != "application/json" && (req.Method != http.MethodGet || media != "application/jwk-set+json")) || resp.Header.Get("Content-Encoding") != "" {
		return result, ErrAuthorityUnavailable
	}
	result.data, err = io.ReadAll(io.LimitReader(resp.Body, int64(limit+1)))
	if err != nil || len(result.data) > limit {
		return remoteJSON{}, ErrAuthorityUnavailable
	}
	return result, nil
}
