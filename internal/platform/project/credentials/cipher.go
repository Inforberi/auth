package credentials

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"regexp"

	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

const Version = 1

var (
	ErrUnavailable = errors.New("project secrets unavailable")
	keyIDPattern   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
)

type Binding struct {
	RealmID       domain.ID
	ProjectID     domain.ID
	ReservationID domain.ID
	StorageTarget string
	DatabaseOID   uint32
	OwnerOID      uint32
	RuntimeOID    uint32
	SchemaVersion int
}

type Codec struct{ root, keyID string }

func New(root, keyID string) (*Codec, error) {
	key, err := base64.StdEncoding.DecodeString(root)
	defer clear(key)
	if err != nil || len(key) != 32 || bytes.Equal(key, make([]byte, 32)) || !keyIDPattern.MatchString(keyID) {
		return nil, ErrUnavailable
	}
	return &Codec{root: root, keyID: keyID}, nil
}

func (c *Codec) KeyID() string { return c.keyID }

func (c *Codec) cipher(binding Binding, version int, keyID string) (*secretbox.Cipher, error) {
	if c == nil || version != Version || keyID != c.keyID || !domain.ValidID(binding.RealmID) || !domain.ValidID(binding.ProjectID) || !domain.ValidID(binding.ReservationID) ||
		!domain.ValidStorageTarget(binding.StorageTarget) || binding.DatabaseOID == 0 || binding.OwnerOID == 0 || binding.RuntimeOID == 0 || binding.SchemaVersion < 1 {
		return nil, ErrUnavailable
	}
	context, err := json.Marshal(struct {
		Purpose string
		Version int
		KeyID   string
		Binding Binding
	}{"project-secrets", version, keyID, binding})
	if err != nil {
		return nil, ErrUnavailable
	}
	cipher, err := secretbox.NewScoped(c.root, string(context))
	if err != nil {
		return nil, ErrUnavailable
	}
	return cipher, nil
}

func (c *Codec) Generate(binding Binding) ([]byte, error) {
	if c == nil {
		return nil, ErrUnavailable
	}
	cipher, err := c.cipher(binding, Version, c.keyID)
	if err != nil {
		return nil, err
	}
	value, err := generate()
	if err != nil {
		return nil, err
	}
	defer clear(value.SigningPrivateKey)
	plain, err := json.Marshal(value)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer clear(plain)
	payload, err := cipher.Seal(plain)
	if err != nil {
		return nil, ErrUnavailable
	}
	return payload, nil
}

func (c *Codec) Verify(binding Binding, version int, keyID string, payload []byte) error {
	value, err := c.open(binding, version, keyID, payload)
	clear(value.SigningPrivateKey)
	return err
}

func (c *Codec) open(binding Binding, version int, keyID string, payload []byte) (material, error) {
	if len(payload) < 128 || len(payload) > 8192 {
		return material{}, ErrUnavailable
	}
	cipher, err := c.cipher(binding, version, keyID)
	if err != nil {
		return material{}, err
	}
	plain, err := cipher.Open(payload)
	if err != nil {
		return material{}, ErrUnavailable
	}
	defer clear(plain)
	var value material
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil || !value.valid() {
		clear(value.SigningPrivateKey)
		return material{}, ErrUnavailable
	}
	if decoder.Decode(new(any)) != io.EOF {
		clear(value.SigningPrivateKey)
		return material{}, ErrUnavailable
	}
	return value, nil
}
