package signing

import (
	"io"
	"os"

	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

type KeyConfig struct {
	Enabled        bool
	Issuer         string
	SigningKeyID   string
	PrivateKeyFile string
	KeySetFile     string
}

// Load is startup-only. It never generates, rewrites or falls back to another key.
func Load(cfg KeyConfig) (*Signer, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	private, err := readKeyFile(cfg.PrivateKeyFile, 16*1024, true)
	if err != nil {
		return nil, err
	}
	defer clear(private)
	public, err := readKeyFile(cfg.KeySetFile, authjwt.MaxJWKSBytes, false)
	if err != nil {
		return nil, err
	}
	keys, err := authjwt.ParsePublicKeys(public)
	if err != nil {
		return nil, err
	}
	return New(cfg.Issuer, cfg.SigningKeyID, private, keys)
}

func readKeyFile(path string, limit int, private bool) (contents []byte, resultErr error) {
	// Deployment paths must not be writable by untrusted users. Stat also avoids opening FIFOs at startup.
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, authjwt.ErrConfiguration
	}
	f, err := os.Open(path) //nolint:gosec // Operator-controlled startup path, never HTTP input; checked regular file/permissions/size.
	if err != nil {
		return nil, authjwt.ErrConfiguration
	}
	defer func() {
		if err := f.Close(); err != nil {
			clear(contents)
			contents, resultErr = nil, authjwt.ErrConfiguration
		}
	}()
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > int64(limit) || private && info.Mode().Perm()&0o077 != 0 {
		return nil, authjwt.ErrConfiguration
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(limit+1)))
	if err != nil || len(data) == 0 || len(data) > limit {
		clear(data)
		return nil, authjwt.ErrConfiguration
	}
	return data, nil
}
