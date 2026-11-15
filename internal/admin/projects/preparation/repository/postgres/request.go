package postgres

import (
	"context"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/internal/sqlerrors"
)

func (r *PreparationRepository) ClaimRequested(ctx context.Context, operation domain.ID) (domain.PreparationRequest, string, error) {
	request := domain.PreparationRequest{OperationID: operation}
	var stage string
	err := r.db.QueryRow(ctx, `UPDATE platform.project_preparation_requests q SET stage=CASE
		WHEN q.stage='managed_configuration_prepared' THEN q.stage ELSE 'running' END,
		attempts=q.attempts+1,retry_after=clock_timestamp()+interval '2 minutes'
		FROM platform.projects p
		WHERE q.operation_id=$1 AND p.id=q.project_id AND p.storage_target=$2 AND p.desired_state='enabled'
		AND ((p.phase='pending' AND p.version=q.expected_version AND p.generation=q.expected_generation)
			OR (p.phase='provisioning' AND p.version=q.expected_version+1 AND p.generation=q.expected_generation+1))
		AND q.stage IN ('requested','running','failed','managed_configuration_prepared')
		RETURNING q.project_id,q.expected_version,q.expected_generation,q.stage`, operation, r.target).
		Scan(&request.ProjectID, &request.ExpectedVersion, &request.ExpectedGeneration, &stage)
	return request, stage, sqlerrors.Catalog(ctx, err)
}

func (r *PreparationRepository) NextRequested(ctx context.Context) (domain.ID, error) {
	var operation domain.ID
	err := r.db.QueryRow(ctx, `SELECT q.operation_id FROM platform.project_preparation_requests q
		JOIN platform.projects p ON p.id=q.project_id
		WHERE q.stage IN ('requested','running','failed','managed_configuration_prepared') AND q.attempts<5
		AND q.retry_after<=clock_timestamp() AND p.storage_target=$1 AND p.desired_state='enabled'
		AND ((p.phase='pending' AND p.version=q.expected_version AND p.generation=q.expected_generation)
			OR (p.phase='provisioning' AND p.version=q.expected_version+1 AND p.generation=q.expected_generation+1))
		ORDER BY q.retry_after,q.operation_id LIMIT 1`, r.target).Scan(&operation)
	return operation, sqlerrors.Catalog(ctx, err)
}

func (r *PreparationRepository) RecordRequestedResult(ctx context.Context, operation domain.ID, stage string) error {
	_, err := r.db.Exec(ctx, `UPDATE platform.project_preparation_requests SET stage=$2 WHERE operation_id=$1 AND stage='running'`, operation, stage)
	return sqlerrors.Catalog(ctx, err)
}
