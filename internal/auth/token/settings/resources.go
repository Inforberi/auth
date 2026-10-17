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

const maxResourceBytes = 1 << 20

func LoadResources(path string) (resources []service.Resource, resultErr error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxResourceBytes {
		return nil, authjwt.ErrConfiguration
	}
	f, err := os.Open(path) //nolint:gosec // Deployment-owned local file, never request input.
	if err != nil {
		return nil, authjwt.ErrConfiguration
	}
	defer func() {
		if err := f.Close(); err != nil {
			resources, resultErr = nil, authjwt.ErrConfiguration
		}
	}()
	if info, err := f.Stat(); err != nil || !info.Mode().IsRegular() {
		return nil, authjwt.ErrConfiguration
	}
	data, err := io.ReadAll(io.LimitReader(f, maxResourceBytes+1))
	if err != nil || len(data) > maxResourceBytes || !utf8.Valid(data) {
		return nil, authjwt.ErrConfiguration
	}
	return decodeResources(data)
}

func decodeResources(data []byte) ([]service.Resource, error) {
	var root map[string]json.RawMessage
	if json.Unmarshal(data, &root) != nil || len(root) != 1 || root["resources"] == nil {
		return nil, authjwt.ErrConfiguration
	}
	var entries []json.RawMessage
	if json.Unmarshal(root["resources"], &entries) != nil || len(entries) == 0 || len(entries) > 32 {
		return nil, authjwt.ErrConfiguration
	}
	resources := make([]service.Resource, 0, len(entries))
	for _, entry := range entries {
		var members map[string]json.RawMessage
		if json.Unmarshal(entry, &members) != nil || len(members) < 2 {
			return nil, authjwt.ErrConfiguration
		}
		for name, value := range members {
			if name != "audience" && name != "mode" && name != "permissions" || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				return nil, authjwt.ErrConfiguration
			}
		}
		var resource service.Resource
		if json.Unmarshal(entry, &resource) != nil {
			return nil, authjwt.ErrConfiguration
		}
		resources = append(resources, resource)
	}
	return resources, nil
}
