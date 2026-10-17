package authjwt

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

var errMissingBearer = errors.New("missing bearer credential")

// Middleware authenticates bearer-only routes; it does not configure browser CORS or cookie routes.
func (c *Consumer) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		raw, err := requestBearer(r)
		if err != nil {
			writeBearerError(w, err)
			return
		}
		p, err := c.Authenticate(r.Context(), raw)
		if err != nil {
			writeBearerError(w, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalContextKey{}, p)))
	})
}

func requestBearer(r *http.Request) (string, error) {
	values := r.Header.Values("Authorization")
	if len(values) == 0 {
		return "", errMissingBearer
	}
	if len(values) != 1 || len(values[0]) > MaxTokenBytes+7 || len(r.Header.Values("Cookie")) != 0 || len(r.URL.RawQuery) > 8192 {
		return "", ErrInvalidToken
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return "", ErrInvalidToken
	}
	for key := range query {
		switch strings.ToLower(key) {
		case "token", "access_token", "id_token", "refresh_token", "authorization":
			return "", ErrInvalidToken
		}
	}
	scheme, raw, found := strings.Cut(values[0], " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || raw == "" || strings.ContainsAny(raw, " \r\n\t,") {
		return "", ErrInvalidToken
	}
	return raw, nil
}

func writeBearerError(w http.ResponseWriter, err error) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	status, body := http.StatusServiceUnavailable, `{"error":"temporarily_unavailable"}`
	switch {
	case errors.Is(err, errMissingBearer):
		status, body = http.StatusUnauthorized, `{"error":"unauthorized"}`
		w.Header().Set("WWW-Authenticate", `Bearer realm="api"`)
	case errors.Is(err, ErrInvalidToken):
		status, body = http.StatusUnauthorized, `{"error":"invalid_token"}`
		w.Header().Set("WWW-Authenticate", `Bearer realm="api", error="invalid_token"`)
	case errors.Is(err, ErrBusy):
		status, body = http.StatusTooManyRequests, `{"error":"rate_limited"}`
		w.Header().Set("Retry-After", "60")
	default:
		w.Header().Set("Retry-After", "1")
	}
	w.WriteHeader(status)
	if _, err := w.Write([]byte(body)); err != nil {
		return
	}
}
