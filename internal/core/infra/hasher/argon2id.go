package hasher

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
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
	ErrPasswordMismatch  = errors.New("password mismatch")
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
	if len(encodedHash) > 4096 {
		return ErrInvalidHashFormat
	}

	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return ErrInvalidHashFormat
	}
	if parts[1] != "argon2id" {
		return ErrInvalidHashFormat
	}
	if parts[2] != "v=19" {
		return ErrInvalidHashFormat
	}
	var memory uint64
	var timeCost uint64
	var threads uint64
	_, err := fmt.Sscanf(
		parts[3],
		"m=%d,t=%d,p=%d",
		&memory,
		&timeCost,
		&threads,
	)
	if err != nil {
		return ErrInvalidHashFormat
	}
	if memory < 8*threads || memory > 256*1024 || timeCost < 1 || timeCost > 10 || threads < 1 || threads > 32 {
		return ErrInvalidHashFormat
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return ErrInvalidHashFormat
	}

	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return ErrInvalidHashFormat
	}
	if len(salt) < 8 || len(salt) > 64 || len(expectedHash) < 16 || len(expectedHash) > 256 {
		return ErrInvalidHashFormat
	}

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		uint32(timeCost),
		uint32(memory),
		uint8(threads),
		uint32(len(expectedHash)), //nolint:gosec // Length is explicitly bounded to 16..256 above.
	)
	if subtle.ConstantTimeCompare(hash, expectedHash) != 1 {
		return ErrPasswordMismatch
	}

	return nil
}
