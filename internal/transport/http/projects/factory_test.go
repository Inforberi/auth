package browser

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	projectprofile "github.com/Inforberi/financial-intelligence/internal/auth/project/profile"
)

type assessmentFactory struct {
	key    projectruntime.Key
	origin string
	calls  int
}

func (f *assessmentFactory) Build(context.Context, projectruntime.Key, string) (*projectprofile.ProjectProfile, error) {
	panic("assessment must not build routable profile")
}

func (f *assessmentFactory) Assess(_ context.Context, key projectruntime.Key, origin string) (projectdomain.AuthPolicyReadiness, error) {
	f.key, f.origin = key, origin
	f.calls++
	return projectdomain.AuthPolicyReadiness{PolicyVersion: 7}, projectdomain.ErrConflict
}

func TestProjectAssessmentUsesInjectedFactory(t *testing.T) {
	factory := &assessmentFactory{}
	h := &ProjectHTTP{factory: factory}
	key := projectruntime.Key{Version: 3, Generation: 2}
	result, err := h.Assess(t.Context(), key, "https://project.example")
	require.ErrorIs(t, err, projectdomain.ErrConflict)
	require.EqualValues(t, 7, result.PolicyVersion)
	require.Equal(t, 1, factory.calls)
	require.Equal(t, key, factory.key)
	require.Equal(t, "https://project.example", factory.origin)
	_, err = (&ProjectHTTP{}).Assess(t.Context(), key, "https://project.example")
	require.ErrorIs(t, err, projectdomain.ErrUnavailable)
}
