package main

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

type projectAccountRequest func(method, path, origin, cookie, body string) (int, []*http.Cookie, []byte)

func (request projectAccountRequest) command(t *testing.T, path, origin, cookie string, input any, expected int, result any) {
	t.Helper()
	request.commandMethod(t, http.MethodPost, path, origin, cookie, input, expected, result)
}

func (request projectAccountRequest) commandMethod(t *testing.T, method, path, origin, cookie string, input any, expected int, result any) []byte {
	t.Helper()
	data, err := json.Marshal(input)
	require.NoError(t, err)
	status, cookies, response := request(method, path, origin, cookie, string(data))
	require.Equal(t, expected, status, "%s: %s", path, response)
	require.Empty(t, cookies, "issuance and activation must not issue a session")
	if result != nil {
		require.NoError(t, json.Unmarshal(response, result))
	}
	return response
}
