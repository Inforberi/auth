package settings

import (
	"bytes"
	"io"
	"os"
	"unicode/utf8"

	"github.com/go-jose/go-jose/v4/json"

	"github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

func LoadIntrospectionClients(path string) (clients []service.IntrospectionClientConfig, resultErr error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 32768 {
		return nil, authjwt.ErrConfiguration
	}
	f, err := os.Open(path) //nolint:gosec // Deployment-owned manifest, never a request path.
	if err != nil {
		return nil, authjwt.ErrConfiguration
	}
	defer func() {
		if f.Close() != nil {
			clients, resultErr = nil, authjwt.ErrConfiguration
		}
	}()
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 32768 {
		return nil, authjwt.ErrConfiguration
	}
	data, err := io.ReadAll(io.LimitReader(f, 32769))
	if err != nil || len(data) > 32768 || !utf8.Valid(data) {
		return nil, authjwt.ErrConfiguration
	}
	return decodeIntrospectionClients(data)
}

func decodeIntrospectionClients(data []byte) ([]service.IntrospectionClientConfig, error) {
	var root map[string]json.RawMessage
	if json.Unmarshal(data, &root) != nil || len(root) != 1 || root["clients"] == nil {
		return nil, authjwt.ErrConfiguration
	}
	var entries []json.RawMessage
	if json.Unmarshal(root["clients"], &entries) != nil || len(entries) == 0 || len(entries) > 32 {
		return nil, authjwt.ErrConfiguration
	}
	clients := make([]service.IntrospectionClientConfig, 0, len(entries))
	for _, entry := range entries {
		var fields map[string]json.RawMessage
		if json.Unmarshal(entry, &fields) != nil || len(fields) != 3 {
			return nil, authjwt.ErrConfiguration
		}
		for _, key := range []string{"id", "secretHashes", "audiences"} {
			if fields[key] == nil || bytes.Equal(bytes.TrimSpace(fields[key]), []byte("null")) {
				return nil, authjwt.ErrConfiguration
			}
		}
		var client service.IntrospectionClientConfig
		if json.Unmarshal(entry, &client) != nil {
			return nil, authjwt.ErrConfiguration
		}
		clients = append(clients, client)
	}
	return clients, nil
}
