package postgres

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/xdg-go/scram"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/credentials"
)

func passwordVerifier(password string) (string, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(password)
	defer clear(decoded)
	if err != nil || len(decoded) != 32 {
		return "", credentials.ErrUnavailable
	}
	var salt [16]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return "", credentials.ErrUnavailable
	}
	// Bootstrap passwords are generated ASCII; library errors must never expose their input.
	client, err := scram.SHA256.NewClient("", password, "")
	if err != nil {
		return "", credentials.ErrUnavailable
	}
	stored, err := client.GetStoredCredentialsWithError(scram.KeyFactors{Salt: string(salt[:]), Iters: 4096})
	if err != nil {
		return "", credentials.ErrUnavailable
	}
	defer clear(stored.StoredKey)
	defer clear(stored.ServerKey)
	return fmt.Sprintf("SCRAM-SHA-256$4096:%s$%s:%s", base64.StdEncoding.EncodeToString(salt[:]),
		base64.StdEncoding.EncodeToString(stored.StoredKey), base64.StdEncoding.EncodeToString(stored.ServerKey)), nil
}
