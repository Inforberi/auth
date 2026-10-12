package settings

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"unicode/utf8"
)

type Config struct {
	CatalogFile string `env:"ACCESS_CATALOG_FILE"`
}

func Load(reader io.Reader) (Document, error) {
	data, err := io.ReadAll(io.LimitReader(reader, MaxCatalogBytes+1))
	if err != nil {
		return Document{}, fmt.Errorf("read catalog: %w", err)
	}
	if len(data) > MaxCatalogBytes || !utf8.Valid(data) {
		return Document{}, ErrInvalidCatalog
	}
	if err := checkJSONKeys(data); err != nil {
		return Document{}, ErrInvalidCatalog
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var definition Definition
	if err := decoder.Decode(&definition); err != nil {
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
