package redis

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/oidc/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/oidc/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

type Repository struct {
	db     *redis.Client
	cipher *secretbox.Cipher
	prefix string
}

func New(db *redis.Client, cipher *secretbox.Cipher, prefix string) *Repository {
	return &Repository{db: db, cipher: cipher, prefix: prefix}
}

func (r *Repository) Save(ctx context.Context, state, binding string, flow domain.Flow) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	plain, err := json.Marshal(flow)
	if err != nil {
		return err
	}
	payload, err := r.cipher.Seal(plain)
	if err != nil {
		return err
	}
	saved, err := r.db.Eval(ctx, `if redis.call('EXISTS',KEYS[1])==1 then return 0 end
		redis.call('HSET',KEYS[1],'binding',ARGV[1],'payload',ARGV[2])
		redis.call('PEXPIRE',KEYS[1],ARGV[3]); return 1`,
		[]string{r.key(state)}, r.cipher.Digest(binding), payload, service.FlowTTL.Milliseconds()).Int()
	if err != nil {
		return err
	}
	if saved != 1 {
		return errors.New("login flow collision")
	}
	return nil
}

func (r *Repository) Consume(ctx context.Context, state, binding string) (*domain.Flow, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	payload, err := r.db.Eval(ctx, `if redis.call('HGET',KEYS[1],'binding')~=ARGV[1] then return nil end
		local p=redis.call('HGET',KEYS[1],'payload'); redis.call('DEL',KEYS[1]); return p`,
		[]string{r.key(state)}, r.cipher.Digest(binding)).Text()
	if errors.Is(err, redis.Nil) {
		return nil, domain.ErrInvalidFlow
	}
	if err != nil {
		return nil, err
	}
	if len(payload) > 1024 {
		return nil, domain.ErrInvalidFlow
	}
	plain, err := r.cipher.Open([]byte(payload))
	if err != nil {
		return nil, domain.ErrInvalidFlow
	}
	var flow domain.Flow
	if err := json.Unmarshal(plain, &flow); err != nil {
		return nil, domain.ErrInvalidFlow
	}
	return &flow, nil
}

func (r *Repository) key(state string) string {
	return r.prefix + ":flow:" + r.cipher.Digest(state)
}

func (r *Repository) Allow(ctx context.Context, ip string, ipLimit, globalLimit int) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	allowed, err := r.db.Eval(ctx, `local n=redis.call('INCR',KEYS[1]);
		if n==1 then redis.call('PEXPIRE',KEYS[1],ARGV[3]) end
		if n>tonumber(ARGV[1]) then return 0 end
		local g=redis.call('INCR',KEYS[2]); if g==1 then redis.call('PEXPIRE',KEYS[2],ARGV[3]) end
		if g>tonumber(ARGV[2]) then return 0 end; return 1`,
		[]string{r.prefix + ":limit:" + r.cipher.Digest(ip), r.prefix + ":limit:global"},
		ipLimit, globalLimit, time.Minute.Milliseconds()).Int()
	return allowed == 1, err
}
