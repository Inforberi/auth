package profile_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/auth/project/profile"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func TestRuntimeProfileOwnsFeatureSnapshot(t *testing.T) {
	states := map[string]profile.ProjectFeatureState{"password": {Feature: "password", Ready: true}}
	runtime := profile.New(profile.Definition{States: states, Policy: settingsdomain.Snapshot{Version: 1}, ObservedAt: time.Now()})
	states["password"] = profile.ProjectFeatureState{Feature: "password", Ready: false, Reason: "changed after assembly"}
	delete(states, "password")
	report := runtime.Readiness()
	require.True(t, report.Ready)
	require.Equal(t, []profile.ProjectFeatureState{{Feature: "password", Ready: true}}, report.Features)
	report.Features[0].Ready = false
	require.True(t, runtime.Readiness().Ready)
}
