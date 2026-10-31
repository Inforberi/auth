package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type controlledOIDCCode struct {
	provider, client, secret, redirect, nonce, challenge string
	used                                                 bool
}

type controlledOIDCProvider struct {
	mu        sync.Mutex
	codes     map[string]controlledOIDCCode
	keys      map[string]*rsa.PrivateKey
	exchanges int
}

func newControlledOIDCProvider(t *testing.T) *controlledOIDCProvider {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	// Only a disposable container may route these fixed production endpoints to this fixture.
	for _, host := range []string{"oauth2.googleapis.com", "www.googleapis.com", "oauth.telegram.org"} {
		addresses, err := net.DefaultResolver.LookupHost(ctx, host)
		require.NoError(t, err)
		require.NotEmpty(t, addresses)
		for _, address := range addresses {
			require.Equal(t, "127.0.0.1", address, "provider aliases must be isolated before any HTTPS request")
		}
	}
	p := &controlledOIDCProvider{codes: map[string]controlledOIDCCode{}, keys: map[string]*rsa.PrivateKey{}}
	for _, name := range []string{"google", "telegram"} {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		p.keys[name] = key
	}
	certificate, trust := controlledOIDCCertificate(t)
	t.Setenv("SSL_CERT_FILE", trust)
	t.Setenv("SSL_CERT_DIR", t.TempDir())
	listener, err := net.Listen("tcp", "127.0.0.1:443")
	require.NoError(t, err, "controlled providers require an unused port443 in their own container")
	server := httptest.NewUnstartedServer(http.HandlerFunc(p.serve))
	server.Listener = listener
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	t.Cleanup(server.Close)
	return p
}

func controlledOIDCCertificate(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"oauth2.googleapis.com", "www.googleapis.com", "oauth.telegram.org"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	private, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: private})
	defer clear(keyPEM)
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "provider-ca.pem")
	require.NoError(t, os.WriteFile(path, certPEM, 0o600))
	return certificate, path
}

func (p *controlledOIDCProvider) serve(w http.ResponseWriter, r *http.Request) {
	name := "google"
	if strings.TrimSuffix(r.Host, ":443") == "oauth.telegram.org" {
		name = "telegram"
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method == "GET" && ((r.Host == "www.googleapis.com" && r.URL.Path == "/oauth2/v3/certs") || (name == "telegram" && r.URL.Path == "/.well-known/jwks.json")) {
		key := p.keys[name]
		public := map[string]string{
			"kty": "RSA", "kid": "fixture-" + name, "alg": "RS256", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{public}})
		return
	}
	if r.Method != "POST" || r.URL.Path != "/token" {
		http.NotFound(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	if r.ParseForm() != nil {
		w.WriteHeader(400)
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.exchanges++
	code, found := p.codes[r.Form.Get("code")]
	id, secret := r.Form.Get("client_id"), r.Form.Get("client_secret")
	if name == "telegram" {
		basicID, basicSecret, ok := r.BasicAuth()
		if !ok || id != "" && basicID != id {
			found = false
		}
		id, secret = basicID, basicSecret
	}
	hash := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
	if !found || code.used || code.provider != name || code.client != id || code.secret != secret || code.redirect != r.Form.Get("redirect_uri") || code.challenge != base64.RawURLEncoding.EncodeToString(hash[:]) || r.Form.Get("grant_type") != "authorization_code" {
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		return
	}
	code.used = true
	p.codes[r.Form.Get("code")] = code
	issuer := "https://accounts.google.com"
	if name == "telegram" {
		issuer = "https://oauth.telegram.org"
	}
	claims := map[string]any{
		"iss": issuer, "sub": "isolated-oidc-subject", "aud": id,
		"iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(),
		"nonce": code.nonce, "email": httpIsolationEmail, "email_verified": true,
	}
	header, err := json.Marshal(map[string]string{"alg": "RS256", "kid": "fixture-" + name})
	if err != nil {
		w.WriteHeader(500)
		return
	}
	body, err := json.Marshal(claims)
	if err != nil {
		w.WriteHeader(500)
		return
	}
	signed := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body)
	digest := sha256.Sum256([]byte(signed))
	signature, err := rsa.SignPKCS1v15(rand.Reader, p.keys[name], crypto.SHA256, digest[:])
	if err != nil {
		w.WriteHeader(500)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": "fixture-only", "token_type": "Bearer", "expires_in": 300,
		"id_token": signed + "." + base64.RawURLEncoding.EncodeToString(signature),
	})
}

func (p *controlledOIDCProvider) register(t *testing.T, name, raw, secret string) (string, string) {
	t.Helper()
	authorization, err := url.Parse(raw)
	require.NoError(t, err)
	q := authorization.Query()
	require.Equal(t, "S256", q.Get("code_challenge_method"))
	for _, field := range []string{"state", "nonce", "code_challenge"} {
		require.Len(t, q.Get(field), 43)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	code := "fixture-code-" + name + "-" + q.Get("state")
	p.codes[code] = controlledOIDCCode{provider: name, client: q.Get("client_id"), secret: secret, redirect: q.Get("redirect_uri"), nonce: q.Get("nonce"), challenge: q.Get("code_challenge")}
	return code, q.Get("state")
}

func (p *controlledOIDCProvider) requests() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.exchanges
}

func (p *controlledOIDCProvider) corrupt(code, field string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	value := p.codes[code]
	if field == "nonce" {
		value.nonce = "wrong-nonce"
	} else {
		value.challenge = "wrong-PKCE-challenge"
	}
	p.codes[code] = value
}
