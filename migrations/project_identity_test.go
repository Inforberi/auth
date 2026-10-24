package migrations_test

import (
	"encoding/hex"
	"testing"

	"github.com/Inforberi/financial-intelligence/migrations"
)

func TestProjectSchemaChecksum(t *testing.T) {
	first := migrations.ProjectSchemaChecksum("runtime grants A")
	decoded, err := hex.DecodeString(first)
	if err != nil || len(decoded) != 32 || first != migrations.ProjectSchemaChecksum("runtime grants A") ||
		first == migrations.ProjectSchemaChecksum("runtime grants B") {
		t.Fatal("invalid or unbound schema checksum")
	}
}
