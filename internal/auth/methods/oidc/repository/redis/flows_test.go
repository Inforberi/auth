package redis

import (
	"encoding/base64"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/oidc/domain"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

func TestRedisFlow(t *testing.T) {
	addr := os.Getenv("AUTH_TELEGRAM_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("explicit disposable Redis not configured")
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil || (host != "127.0.0.1" && host != "localhost") {
		t.Fatal("dedicated localhost Redis required")
	}
	db := redis.NewClient(&redis.Options{Addr: addr, MaxRetries: -1})
	defer func() { _ = db.Close() }()
	if size, err := db.DBSize(t.Context()).Result(); err != nil || size != 0 {
		t.Fatal("fixture must be fresh and empty", size, err)
	}
	cipher, err := secretbox.NewScoped(base64.StdEncoding.EncodeToString(make([]byte, 32)), "telegram-login:v1")
	if err != nil {
		t.Fatal(err)
	}
	repo := New(db, cipher, "auth:telegram")
	googleCipher, err := secretbox.NewScoped(base64.StdEncoding.EncodeToString(make([]byte, 32)), "google-login:v1")
	if err != nil {
		t.Fatal(err)
	}
	google := New(db, googleCipher, "auth:google")
	flow := domain.Flow{Verifier: "fixture-verifier", Nonce: "fixture-nonce", Purpose: domain.Link, UserID: "12345678-1234-1234-1234-123456789abc", SessionHash: strings.Repeat("a", 64)}
	if err := repo.Save(t.Context(), "state", "binding", flow); err != nil {
		t.Fatal(err)
	}
	if ttl, err := db.PTTL(t.Context(), repo.key("state")).Result(); err != nil || ttl > 5*time.Minute || ttl < 4*time.Minute {
		t.Fatal("flow not bounded", ttl, err)
	}
	if payload, err := db.HGet(t.Context(), repo.key("state"), "payload").Result(); err != nil || strings.Contains(payload, flow.Verifier) || strings.Contains(payload, string(flow.UserID)) || strings.Contains(payload, flow.SessionHash) {
		t.Fatal("verifier stored as plaintext", err)
	}
	if err := repo.Save(t.Context(), "state", "other-binding", flow); err == nil {
		t.Fatal("flow overwritten")
	}
	if _, err := repo.Consume(t.Context(), "state", "wrong-browser"); !errors.Is(err, domain.ErrInvalidFlow) {
		t.Fatal(err)
	}
	if _, err := google.Consume(t.Context(), "state", "binding"); !errors.Is(err, domain.ErrInvalidFlow) {
		t.Fatal("cross-provider consume", err)
	}
	if err := google.Save(t.Context(), "state", "binding", flow); err != nil {
		t.Fatal(err)
	}
	if _, err := google.Consume(t.Context(), "state", "binding"); err != nil {
		t.Fatal("Google isolated state", err)
	}
	if ok, err := google.Allow(t.Context(), "ip", 1, 1); err != nil || !ok {
		t.Fatal("Google budget", err)
	}
	var successes atomic.Int64
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			got, err := repo.Consume(t.Context(), "state", "binding")
			if err == nil {
				if *got != flow {
					t.Error("corrupted flow")
				}
				successes.Add(1)
			} else if !errors.Is(err, domain.ErrInvalidFlow) {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatal("consume not single-use", successes.Load())
	}
	if err := repo.Save(t.Context(), "expired", "binding", flow); err != nil {
		t.Fatal(err)
	}
	if err := db.PExpire(t.Context(), repo.key("expired"), 0).Err(); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Consume(t.Context(), "expired", "binding"); !errors.Is(err, domain.ErrInvalidFlow) {
		t.Fatal("expired flow accepted", err)
	}
	var allowed atomic.Int64
	for range 32 {
		wg.Go(func() {
			ok, err := repo.Allow(t.Context(), "ip", 10, 100)
			if err != nil {
				t.Error(err)
			}
			if ok {
				allowed.Add(1)
			}
		})
	}
	wg.Wait()
	if allowed.Load() != 10 {
		t.Fatal("distributed IP budget failed", allowed.Load())
	}
	if ok, err := repo.Allow(t.Context(), "other-ip", 10, 10); err != nil || ok {
		t.Fatal("global budget bypassed", ok, err)
	}
	if ok, err := google.Allow(t.Context(), "other-ip", 10, 1); err != nil || ok {
		t.Fatal("Google project budget", ok, err)
	}
	if err := db.HSet(t.Context(), repo.key("tampered"), "binding", cipher.Digest("binding"), "payload", "invalid").Err(); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Consume(t.Context(), "tampered", "binding"); !errors.Is(err, domain.ErrInvalidFlow) {
		t.Fatal("tampered ciphertext accepted", err)
	}
}
