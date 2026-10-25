package settings

import (
	"fmt"
	"io"
	"os"

	"github.com/Inforberi/financial-intelligence/internal/infra/jsonconfig"
)

type Config struct {
	CatalogFile string `env:"ACCESS_CATALOG_FILE"`
}

func Load(reader io.Reader) (Document, error) {
	data, err := io.ReadAll(io.LimitReader(reader, MaxCatalogBytes+1))
	if err != nil {
		return Document{}, fmt.Errorf("read catalog: %w", err)
	}
	if len(data) > MaxCatalogBytes {
		return Document{}, ErrInvalidCatalog
	}
	var definition Definition
	if err := jsonconfig.Decode(data, &definition); err != nil {
		return Document{}, ErrInvalidCatalog
	}
	return NewDocument(definition)
}

func LoadFile(path string) (document Document, err error) {
	if path == "" {
		return NewDocument(Definition{Version: FormatVersion})
	}
	info, err := os.Stat(path)
	if err != nil {
		return Document{}, fmt.Errorf("stat catalog file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > MaxCatalogBytes {
		return Document{}, ErrInvalidCatalog
	}
	file, err := os.Open(path) //nolint:gosec // Operator-controlled local configuration path, never a browser-supplied URL/path.
	if err != nil {
		return Document{}, fmt.Errorf("open catalog file: %w", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil && err == nil {
			document = Document{}
			err = fmt.Errorf("close catalog file: %w", closeErr)
		}
	}()
	return Load(file)
}
