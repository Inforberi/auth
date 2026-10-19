package credentials

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
)

type material struct {
	DatabasePassword  string `json:"databasePassword"`
	EncryptionKey     string `json:"encryptionKey"`
	SetupSecret       string `json:"setupSecret"`
	SigningKeyID      string `json:"signingKeyId"`
	SigningPrivateKey []byte `json:"signingPrivateKey"`
}

func generate() (material, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return material{}, ErrUnavailable
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return material{}, ErrUnavailable
	}
	defer clear(der)
	var random [112]byte
	if _, err := rand.Read(random[:]); err != nil {
		return material{}, ErrUnavailable
	}
	defer clear(random[:])
	return material{
		DatabasePassword:  base64.RawURLEncoding.EncodeToString(random[:32]),
		EncryptionKey:     base64.StdEncoding.EncodeToString(random[32:64]),
		SetupSecret:       base64.RawURLEncoding.EncodeToString(random[64:96]),
		SigningKeyID:      "p1-" + base64.RawURLEncoding.EncodeToString(random[96:]),
		SigningPrivateKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
	}, nil
}

func (m material) valid() bool {
	db, e1 := base64.RawURLEncoding.DecodeString(m.DatabasePassword)
	root, e2 := base64.StdEncoding.DecodeString(m.EncryptionKey)
	setup, e3 := base64.RawURLEncoding.DecodeString(m.SetupSecret)
	defer clear(db)
	defer clear(root)
	defer clear(setup)
	if e1 != nil || e2 != nil || e3 != nil || len(db) != 32 || len(root) != 32 || len(setup) != 32 || len(m.SigningKeyID) != 25 {
		return false
	}
	block, rest := pem.Decode(m.SigningPrivateKey)
	if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
		return false
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return false
	}
	ec, ok := key.(*ecdsa.PrivateKey)
	return ok && ec.Curve == elliptic.P256()
}
