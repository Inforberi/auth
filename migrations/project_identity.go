package migrations

import (
	"crypto/sha256"
	"encoding/hex"
)

// ProjectIdentityView exposes installed identity only, never setup hashes or keys.
const ProjectIdentityView = `CREATE VIEW auth.project_identity AS
SELECT realm_id,project_id,reservation_id,database_oid,owner_oid,runtime_oid,schema_version,schema_checksum
FROM project_meta.identity WHERE singleton;
REVOKE ALL ON auth.project_identity FROM PUBLIC;`

func ProjectSchemaChecksum(runtimeGrants string) string {
	digest := sha256.Sum256([]byte(InitialAuth() + "\x00" + runtimeGrants + "\x00" + ProjectIdentityView))
	return hex.EncodeToString(digest[:])
}
