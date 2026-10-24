package postgres

// Both cold credential reads and resident-state probes use this exact match.
// wanted is a typed SQL input row, not data supplied by an HTTP request.
const runtimeSnapshotRelations = `platform.projects p
	JOIN platform.project_preparations prep ON prep.project_id=p.id
	JOIN platform.project_secrets s ON s.project_id=p.id
	CROSS JOIN platform.operator_realm realm`

const runtimeSnapshotPredicate = `realm.id=wanted.realm_id AND realm.initialized_at IS NOT NULL
	AND p.id=wanted.project_id AND s.reservation_id=wanted.reservation_id
	AND prep.reservation_id=s.reservation_id AND prep.secrets_created
	AND p.storage_target=wanted.storage_target AND s.storage_target=p.storage_target AND prep.storage_target=p.storage_target
	AND s.database_oid=wanted.database_oid AND s.owner_oid=wanted.owner_oid AND s.runtime_oid=wanted.runtime_oid
	AND s.schema_version=wanted.schema_version AND p.schema_version=s.schema_version
	AND p.version=wanted.version AND p.generation=wanted.generation AND p.desired_state='enabled' AND p.phase='ready'
	AND p.database_name='authp_'||replace(p.id::text,'-','') AND p.credential_ref IS NOT NULL`
