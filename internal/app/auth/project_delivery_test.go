package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	passwordrecovery "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/recovery/service"
)

func TestProjectEmailTrustedURLs(t *testing.T) {
	cfg := ProjectEmailConfig{VerificationEnabled: true, RecoveryEnabled: true, Origin: "https://project.example.test", Verification: accountservice.Config{
		URL: "https://project.example.test/verify-email", EncryptionKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)),
		TTL: 30 * time.Minute, ResendInterval: time.Minute, RegistrationIPLimit: 5, RegistrationGlobalLimit: 100,
	}, Password: passwordrecovery.Config{ResetURL: "https://project.example.test/reset-password", ResetTokenTTL: time.Hour, ResetGlobalLimit: 100}}
	require.NoError(t, cfg.validate())
	for _, raw := range []string{"https://platform.example.test/reset", "http://project.example.test/reset", "https://user:secret@project.example.test/reset", "https://project.example.test/reset?next=https://evil.example", "https://project.example.test/reset#fragment"} {
		bad := cfg
		bad.Password.ResetURL = raw
		require.Error(t, bad.validate(), raw)
	}
	cfg.Verification.URL = "https://other.example.test/verify-email"
	require.Error(t, cfg.validate())
}

func TestProjectDeliveryPageBounds(t *testing.T) {
	keys := make([]projectruntime.Key, 9)
	for i := range keys {
		keys[i].Version = int64(i + 1)
	}
	var active, maximum atomic.Int32
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	done := make(chan struct{})
	visited := make([]atomic.Int32, len(keys))
	var errorsSeen int
	failure := errors.New("synthetic delivery error")
	go func() {
		defer close(done)
		deliverProjectPage(t.Context(), keys, 2, func(_ context.Context, key projectruntime.Key) error {
			n := active.Add(1)
			for old := maximum.Load(); n > old; old = maximum.Load() {
				if maximum.CompareAndSwap(old, n) {
					break
				}
			}
			visited[key.Version-1].Add(1)
			if key.Version <= 2 {
				started <- struct{}{}
				<-release
			}
			active.Add(-1)
			if key.Version == 3 {
				return failure
			}
			return nil
		}, func(err error) {
			if errors.Is(err, failure) {
				errorsSeen++
			}
		})
	}()
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	for range 2 {
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			t.Fatal("bounded workers did not start")
		}
	}
	require.EqualValues(t, 2, active.Load())
	close(release)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("delivery workers did not drain")
	}
	require.EqualValues(t, 2, maximum.Load())
	for i := range visited {
		require.EqualValues(t, 1, visited[i].Load())
	}
	require.Equal(t, 1, errorsSeen)
}

func TestProjectDeliveryPageCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	count := 0
	deliverProjectPage(ctx, make([]projectruntime.Key, 8), 1, func(context.Context, projectruntime.Key) error {
		count++
		cancel()
		return ctx.Err()
	}, func(error) { t.Error("shutdown cancellation must not be reported as delivery failure") })
	require.Equal(t, 1, count)
}
