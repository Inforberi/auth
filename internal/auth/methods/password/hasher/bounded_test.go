package hasher

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
)

type blockingHash struct {
	started chan struct{}
	release chan struct{}
	calls   atomic.Int64
}

func (h *blockingHash) GenerateHash([]byte) (string, error) {
	h.calls.Add(1)
	h.started <- struct{}{}
	<-h.release
	return "hash", nil
}

func (h *blockingHash) Compare(string, string) error {
	_, err := h.GenerateHash(nil)
	return err
}

func TestSharedHashBudget(t *testing.T) {
	backend := &blockingHash{started: make(chan struct{}, 2), release: make(chan struct{})}
	hash := NewBounded(backend, 2)
	var workers sync.WaitGroup
	workers.Go(func() {
		_, err := hash.GenerateHash(t.Context(), nil)
		if err != nil {
			t.Error(err)
		}
	})
	workers.Go(func() {
		if err := hash.Compare(t.Context(), "password", "hash"); err != nil {
			t.Error(err)
		}
	})
	<-backend.started
	<-backend.started
	var burst sync.WaitGroup
	for range 1000 {
		burst.Go(func() {
			if err := hash.Compare(t.Context(), "password", "hash"); !errors.Is(err, domain.ErrHashBusy) {
				t.Error(err)
			}
		})
	}
	burst.Wait()
	if backend.calls.Load() != 2 {
		t.Fatal("overload reached Argon2")
	}
	close(backend.release)
	workers.Wait()
	if _, err := hash.GenerateHash(t.Context(), nil); err != nil {
		t.Fatal("slot leaked", err)
	}
}

func TestHashCancellationKeepsSlotUntilCompletion(t *testing.T) {
	backend := &blockingHash{started: make(chan struct{}, 2), release: make(chan struct{})}
	hash := NewBounded(backend, 1)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { _, err := hash.GenerateHash(ctx, nil); done <- err }()
	<-backend.started
	cancel()
	if err := hash.Compare(t.Context(), "password", "hash"); !errors.Is(err, domain.ErrHashBusy) {
		t.Fatal("cancel freed live Argon2 slot", err)
	}
	close(backend.release)
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled hash result accepted", err)
	}
	if _, err := hash.GenerateHash(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if backend.calls.Load() != 1 {
		t.Fatal("cancelled request started hashing")
	}
}
