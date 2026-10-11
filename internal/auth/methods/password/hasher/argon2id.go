package hasher

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
)

type Argon2idHash struct {
	time    uint32
	memory  uint32
	threads uint8
	keyLen  uint32
	saltLen uint32
}

var (
	ErrInvalidHashFormat = errors.New("invalid password hash format")
	ErrPasswordMismatch  = domain.ErrPasswordHashMismatch
)

func NewArgon2idHash(time, saltLen, memory uint32, threads uint8, keyLen uint32) *Argon2idHash {
	return &Argon2idHash{
		time:    time,
		saltLen: saltLen,
		memory:  memory,
		threads: threads,
		keyLen:  keyLen,
	}
}

func randomSecret(length uint32) ([]byte, error) {
	secret := make([]byte, length)

	_, err := rand.Read(secret)
	if err != nil {
		return nil, err
	}

	return secret, nil
}

func (a *Argon2idHash) GenerateHash(password []byte) (string, error) {
	salt, err := randomSecret(a.saltLen)
	if err != nil {
		return "", err
	}

	hash := argon2.IDKey(
		password,
		salt,
		a.time,
		a.memory,
		a.threads,
		a.keyLen,
	)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encoded := fmt.Sprintf(
		"$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		a.memory,
		a.time,
		a.threads,
		b64Salt,
		b64Hash,
	)

	return encoded, nil
}

func (a *Argon2idHash) Compare(password, encodedHash string) error {
	p, err := parse(encodedHash)
	if err != nil {
		return err
	}
	hash := argon2.IDKey([]byte(password), p.salt, p.time, p.memory, p.threads, uint32(len(p.key))) //nolint:gosec // Parser bounds the key length to 16..256.
	if subtle.ConstantTimeCompare(hash, p.key) != 1 {
		return ErrPasswordMismatch
	}
	return nil
}
