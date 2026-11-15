package schema

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	authschema "github.com/Inforberi/financial-intelligence/migrations/auth"
)

// ProjectIdentityView exposes installed identity only, never setup hashes or keys.
const ProjectIdentityView = `CREATE VIEW auth.project_identity AS
SELECT realm_id,project_id,reservation_id,database_oid,owner_oid,runtime_oid,schema_version,schema_checksum
FROM project_meta.identity WHERE singleton;
REVOKE ALL ON auth.project_identity FROM PUBLIC;`

func ProjectSchemaChecksum(runtimeGrants string) string {
	// Existing project markers predate the append-only lifecycle grants.
	// Their effective ACLs are checked separately from the bootstrap fingerprint.
	if before, block, ok := strings.Cut(runtimeGrants, "-- BEGIN platform lifecycle grants\n"); ok {
		if _, after, ok := strings.Cut(block, "-- END platform lifecycle grants\n"); ok {
			runtimeGrants = before + after
		}
	}
	digest := sha256.Sum256([]byte(authschema.InitialAuth() + "\x00" + runtimeGrants + "\x00" + ProjectIdentityView))
	return hex.EncodeToString(digest[:])
}
