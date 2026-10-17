package service

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"

	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

type IntrospectionClientConfig struct {
	ID           string   `json:"id"`
	SecretHashes []string `json:"secretHashes"`
	Audiences    []string `json:"audiences"`
}

type IntrospectionClient struct {
	id        string
	verifiers [][32]byte
	audiences map[string]bool
}

func introspectionClients(configs []IntrospectionClientConfig, resources map[string]resourcePolicy) (map[string]*IntrospectionClient, error) {
	if len(configs) == 0 || len(configs) > 32 {
		return nil, authjwt.ErrConfiguration
	}
	clients := make(map[string]*IntrospectionClient, len(configs))
	for _, cfg := range configs {
		if !authjwt.ValidKeyID(cfg.ID) || clients[cfg.ID] != nil || len(cfg.SecretHashes) < 1 || len(cfg.SecretHashes) > 2 || len(cfg.Audiences) < 1 || len(cfg.Audiences) > 32 {
			return nil, authjwt.ErrConfiguration
		}
		client := &IntrospectionClient{id: cfg.ID, audiences: make(map[string]bool, len(cfg.Audiences))}
		for _, encoded := range cfg.SecretHashes {
			hash, err := hex.DecodeString(encoded)
			if err != nil || len(hash) != sha256.Size || hex.EncodeToString(hash) != encoded {
				return nil, authjwt.ErrConfiguration
			}
			verifier := [32]byte(hash)
			for _, previous := range client.verifiers {
				if previous == verifier {
					return nil, authjwt.ErrConfiguration
				}
			}
			client.verifiers = append(client.verifiers, verifier)
		}
		for _, audience := range cfg.Audiences {
			if _, exists := resources[audience]; !exists || client.audiences[audience] {
				return nil, authjwt.ErrConfiguration
			}
			client.audiences[audience] = true
		}
		clients[cfg.ID] = client
	}
	return clients, nil
}

func (s *Introspection) Authenticate(id, secret string) (*IntrospectionClient, bool) {
	client := s.clients[id]
	if client == nil || len(secret) != 43 {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != secret {
		return nil, false
	}
	// Hash the presented textual credential; manifest verifiers never contain usable secrets.
	hash := sha256.Sum256([]byte(secret))
	matched := 0
	for _, verifier := range client.verifiers {
		matched |= subtle.ConstantTimeCompare(hash[:], verifier[:])
	}
	if matched != 1 {
		return nil, false
	}
	return client, true
}
