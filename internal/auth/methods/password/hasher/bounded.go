package hasher

import (
	"context"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
)

type passwordHasher interface {
	NeedsRehash(string) bool
	GenerateHash([]byte) (string, error)
	Compare(string, string) error
}

func (h *Bounded) NeedsRehash(encoded string) bool {
	return h.hash.NeedsRehash(encoded)
}

type Bounded struct {
	hash  passwordHasher
	slots chan struct{}
}

func NewBounded(hash passwordHasher, concurrency int) *Bounded {
	if concurrency < 1 {
		panic("password hash concurrency must be positive")
	}
	return &Bounded{hash: hash, slots: make(chan struct{}, concurrency)}
}

func (h *Bounded) GenerateHash(ctx context.Context, password []byte) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
		hash, err := h.hash.GenerateHash(password)
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return hash, err
	default:
		return "", domain.ErrHashBusy
	}
}

func (h *Bounded) Compare(ctx context.Context, password, encoded string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
		err := h.hash.Compare(password, encoded)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	default:
		return domain.ErrHashBusy
	}
}
