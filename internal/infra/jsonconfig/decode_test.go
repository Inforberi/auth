package jsonconfig

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecodeRejectsAmbiguousConfiguration(t *testing.T) {
	for _, input := range []string{`{"value":1,"value":2}`, `{"value":1,"Value":2}`, `{"value":1} {}`, `{"unknown":1}`, string([]byte{'{', '"', 'v', 'a', 'l', 'u', 'e', '"', ':', '"', 255, '"', '}'})} {
		t.Run(input, func(t *testing.T) {
			var result struct {
				Value any `json:"value"`
			}
			require.ErrorIs(t, Decode([]byte(input), &result), ErrInvalidJSON)
		})
	}
	var result struct {
		Value int `json:"value"`
	}
	require.NoError(t, Decode([]byte(`{"value":1}`), &result))
	require.Equal(t, 1, result.Value)
}
