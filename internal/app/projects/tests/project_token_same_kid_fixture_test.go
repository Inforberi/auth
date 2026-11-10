package projects_test

import (
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/credentials"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

type projectSigningFixtureBundle struct {
	DatabasePassword  string `json:"databasePassword"`
	EncryptionKey     string `json:"encryptionKey"`
	SetupSecret       string `json:"setupSecret"`
	SigningKeyID      string `json:"signingKeyId"`
	SigningPrivateKey []byte `json:"signingPrivateKey"`
}

// setProjectTokenFixtureKID changes only the encrypted signing-key identifier
// in the disposable project fixture; each project's generated private key stays independent.
func setProjectTokenFixtureKID(t *testing.T, projects projectIsolationHTTP, root, kid string) {
	t.Helper()
	var privateKeyDigests [2][32]byte
	for i, project := range projects.projects {
		binding := project.Binding
		var version int
		var rootKeyID string
		var ciphertext []byte
		require.NoError(t, projects.admin.QueryRow(t.Context(), `
			SELECT format_version,key_id,ciphertext FROM platform.project_secrets WHERE project_id=$1`, binding.ProjectID).
			Scan(&version, &rootKeyID, &ciphertext))
		contextBytes, err := json.Marshal(struct {
			Purpose string
			Version int
			KeyID   string
			Binding credentials.Binding
		}{"project-secrets", version, rootKeyID, binding})
		require.NoError(t, err)
		cipher, err := secretbox.NewScoped(root, string(contextBytes))
		require.NoError(t, err)
		plain, err := cipher.Open(ciphertext)
		require.NoError(t, err)
		var bundle projectSigningFixtureBundle
		require.NoError(t, json.Unmarshal(plain, &bundle))
		clear(plain)
		privateKeyDigests[i] = sha256.Sum256(bundle.SigningPrivateKey)
		bundle.SigningKeyID = kid
		plain, err = json.Marshal(bundle)
		require.NoError(t, err)
		sealed, err := cipher.Seal(plain)
		clear(plain)
		clear(bundle.SigningPrivateKey)
		require.NoError(t, err)
		_, err = projects.admin.Exec(t.Context(), `UPDATE platform.project_secrets SET ciphertext=$2 WHERE project_id=$1`, binding.ProjectID, sealed)
		require.NoError(t, err)
	}
	require.NotEqual(t, privateKeyDigests[0], privateKeyDigests[1], "same kid fixture must retain distinct project private keys")
}
