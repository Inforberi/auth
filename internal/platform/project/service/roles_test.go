package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

type roleRepositoryStub struct {
	prepared, executed bool
	err                error
}

func (s *roleRepositoryStub) PrepareRoleCreation(context.Context, operatordomain.Principal, domain.RoleCreation) (domain.RoleCreationIntent, error) {
	s.prepared = true
	return domain.RoleCreationIntent{}, s.err
}

func (s *roleRepositoryStub) ExecuteRoleCreation(context.Context, operatordomain.Principal, domain.RoleCreation) (domain.RoleCreationResult, error) {
	s.executed = s.prepared
	return domain.RoleCreationResult{}, nil
}

func (s *roleRepositoryStub) ReadRoleOutcome(context.Context, operatordomain.Principal, domain.ID, domain.ID) (domain.RoleCreationOutcome, error) {
	return domain.RoleCreationOutcome{}, s.err
}

func (s *roleRepositoryStub) ReconcileRoleOutcome(context.Context, operatordomain.Principal, domain.ID, domain.ID) (domain.RoleCreationOutcome, error) {
	return domain.RoleCreationOutcome{}, s.err
}

func TestRoleCreationRequiresPreparedIntent(t *testing.T) {
	for _, err := range []error{nil, operatordomain.ErrForbidden, domain.ErrConflict} {
		repo := &roleRepositoryStub{err: err}
		_, actual := NewRoles(repo).CreateRole(t.Context(), operatordomain.Principal{}, domain.RoleCreation{})
		if err == nil {
			require.NoError(t, actual)
			require.True(t, repo.executed)
		} else {
			require.ErrorIs(t, actual, err)
			require.False(t, repo.executed)
		}
	}
}
