package service_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	roleservice "github.com/Inforberi/financial-intelligence/internal/admin/projects/roles/service"
)

type reconciliationStub struct {
	found              bool
	readErr, recordErr error
	recorded           bool
	bounded            bool
}

func (s *reconciliationStub) ReadReceipt(ctx context.Context) (bool, error) {
	_, s.bounded = ctx.Deadline()
	return s.found, s.readErr
}

func (s *reconciliationStub) RecordReceipt(context.Context) error {
	s.recorded = true
	return s.recordErr
}

func TestRoleReconciliationStopsBeforeProjectForKnownOrForbidden(t *testing.T) {
	for _, err := range []error{nil, operatordomain.ErrForbidden} {
		repo := &roleRepositoryStub{outcomes: []domain.RoleOutcome{{Committed: true}}, err: err}
		result, actual := roleservice.NewRoles(repo).ReconcileRoleOutcome(t.Context(), operatordomain.Principal{}, "project", "operation")
		require.ErrorIs(t, actual, err)
		require.True(t, result.Committed)
		require.Zero(t, repo.preparations)
	}
}

func TestRoleReconciliationRecordsOnlyConfirmedReceipt(t *testing.T) {
	for _, tc := range []struct {
		name       string
		job        *reconciliationStub
		wantErr    error
		wantRecord bool
		wantReads  int
	}{
		{"missing receipt", &reconciliationStub{}, nil, false, 2},
		{"receipt read failed", &reconciliationStub{found: true, readErr: domain.ErrUnavailable}, domain.ErrUnavailable, false, 1},
		{"catalog write failed", &reconciliationStub{found: true, recordErr: domain.ErrConflict}, domain.ErrConflict, true, 1},
		{"recovered receipt", &reconciliationStub{found: true}, nil, true, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &roleRepositoryStub{reconciliation: tc.job, outcomes: []domain.RoleOutcome{{}, {Committed: tc.job.found}}}
			result, err := roleservice.NewRoles(repo).ReconcileRoleOutcome(t.Context(), operatordomain.Principal{}, "project", "operation")
			require.ErrorIs(t, err, tc.wantErr)
			require.Equal(t, tc.wantRecord, tc.job.recorded)
			require.Equal(t, tc.wantReads, repo.reads)
			require.True(t, tc.job.bounded)
			if err == nil {
				require.Equal(t, tc.job.found, result.Committed)
			}
		})
	}
}

func TestRoleReconciliationPreparationFailsClosed(t *testing.T) {
	for _, err := range []error{nil, domain.ErrConflict} {
		repo := &roleRepositoryStub{prepareErr: err}
		_, actual := roleservice.NewRoles(repo).ReconcileRoleOutcome(t.Context(), operatordomain.Principal{}, "project", "operation")
		if err == nil {
			require.ErrorIs(t, actual, domain.ErrUnavailable)
		} else {
			require.ErrorIs(t, actual, err)
		}
		require.Equal(t, 1, repo.reads)
	}
}
