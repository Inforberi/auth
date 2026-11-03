package service

import (
	"crypto/sha256"
	"encoding/hex"
)

func TokenDigest(token string) string {
	d := sha256.Sum256([]byte(token))
	return hex.EncodeToString(d[:])
}
