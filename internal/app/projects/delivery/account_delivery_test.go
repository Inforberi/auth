package delivery

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProjectAccountDeliveryFairnessAcrossSweeps(t *testing.T) {
	seen := [4]int{}
	for turn := uint8(0); turn < 8; turn++ {
		cfg := projectAccountDelivery(turn)
		kinds := []bool{!cfg.EmailChanges && !cfg.Invitations && !cfg.EmailBinding, cfg.EmailChanges, cfg.Invitations, cfg.EmailBinding}
		chosen := 0
		for i, enabled := range kinds {
			if enabled {
				seen[i]++
				chosen++
			}
		}
		require.Equal(t, 1, chosen, "each sweep prioritizes exactly one queue, with verification fallback")
	}
	require.Equal(t, [4]int{2, 2, 2, 2}, seen, "continuous backlog in any queue must not starve another across full sweeps")
}
