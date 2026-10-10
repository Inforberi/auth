package redis

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

func TestDistributedLoginLimits(t *testing.T) {
	addr := os.Getenv("AUTH_LOGIN_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("dedicated disposable Redis not configured")
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host != "127.0.0.1" {
		t.Fatal("fixture must use loopback")
	}
	cipher, err := secretbox.NewScoped("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "login-test:"+t.Name()+time.Now().Format("150405.000000000"))
	if err != nil {
		t.Fatal(err)
	}
	var clients []*redis.Client
	var limits []*service.LoginLimit
	for range 2 {
		client := redis.NewClient(&redis.Options{Addr: addr, MaxRetries: -1, ContextTimeoutEnabled: true})
		t.Cleanup(func() { _ = client.Close() })
		clients = append(clients, client)
		limits = append(limits, service.NewLoginLimit(New(client), cipher, service.CapacityConfig{LoginIPLimit: 30, LoginEmailLimit: 10, LoginGlobalLimit: 10}))
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var accepted atomic.Int64
	var burst sync.WaitGroup
	for i := range 200 {
		burst.Go(func() {
			err := limits[i%2].Allow(ctx, fmt.Sprintf("user-%d@example.com", i), fmt.Sprintf("192.0.2.%d", i))
			if err == nil {
				accepted.Add(1)
			} else if !errors.Is(err, domain.ErrLoginLimited) {
				t.Error(err)
			}
		})
	}
	burst.Wait()
	if accepted.Load() != 10 {
		t.Fatal("replicas multiplied shared quota", accepted.Load())
	}
	ttl, err := clients[0].PTTL(ctx, "auth:password-recovery:limit:"+cipher.Digest("login-global")).Result()
	if err != nil || ttl <= 0 || ttl > time.Minute {
		t.Fatal("unbounded limiter key lifetime", ttl, err)
	}
	for _, client := range clients {
		if err := client.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := limits[0].Allow(ctx, "user@example.com", "ip"); !errors.Is(err, domain.ErrLoginUnavailable) {
		t.Fatal("Redis failure opened login", err)
	}
}
