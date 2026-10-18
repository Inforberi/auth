package auth

import (
	"context"
	"errors"
	stdlog "log"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	otpservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/hasher"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
)

func TestRealmRequiresBorrowedDependencies(t *testing.T) {
	// Only dependency validation runs here; empty adapters must never receive a call.
	complete := realmDependencies{pool: &pgxpool.Pool{}, redis: &redis.Client{}, log: zap.NewNop(), hash: hasher.NewBounded(&blockingHash{}, 1), scope: realmscope.Legacy()}
	for _, missing := range []string{"pool", "redis", "logger", "hasher", "scope"} {
		t.Run(missing, func(t *testing.T) {
			deps := complete
			switch missing {
			case "pool":
				deps.pool = nil
			case "redis":
				deps.redis = nil
			case "logger":
				deps.log = nil
			case "hasher":
				deps.hash = nil
			case "scope":
				deps.scope = realmscope.Scope{}
			}
			writer, flags, prefix := stdlog.Writer(), stdlog.Flags(), stdlog.Prefix()
			assembled, err := assembleRealm(t.Context(), &config.Config{}, deps)
			if assembled != nil || err == nil {
				t.Fatal("incomplete realm was assembled")
			}
			if writer != stdlog.Writer() || flags != stdlog.Flags() || prefix != stdlog.Prefix() {
				t.Fatal("realm assembly redirected the process logger")
			}
		})
	}
}

type blockingHash struct{ entered, release chan struct{} }

func (*blockingHash) NeedsRehash(string) bool { return false }

func (h *blockingHash) GenerateHash([]byte) (string, error) {
	close(h.entered)
	<-h.release
	return "fixture hash", nil
}

func (*blockingHash) Compare(string, string) error { return nil }

func TestRealmsShareHashBudget(t *testing.T) {
	engine := &blockingHash{entered: make(chan struct{}), release: make(chan struct{})}
	shared := hasher.NewBounded(engine, 1)
	first, second := realmDependencies{hash: shared}, realmDependencies{hash: shared}
	done := make(chan error, 1)
	go func() {
		_, err := first.hash.GenerateHash(t.Context(), []byte("password"))
		done <- err
	}()
	<-engine.entered
	_, generateErr := second.hash.GenerateHash(t.Context(), []byte("password"))
	compareErr := second.hash.Compare(t.Context(), "password", "fixture hash")
	close(engine.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !errors.Is(generateErr, passworddomain.ErrHashBusy) || !errors.Is(compareErr, passworddomain.ErrHashBusy) {
		t.Fatal("another realm bypassed the process hash budget")
	}
	if err := second.hash.Compare(t.Context(), "password", "fixture hash"); err != nil {
		t.Fatal("hash slot was not released", err)
	}
}

type testRetentionWorker struct{ started, stopped chan struct{} }

func (w *testRetentionWorker) RunRetention(ctx context.Context, _ func(error)) {
	close(w.started)
	<-ctx.Done()
	close(w.stopped)
}

func TestRealmLifecycleBeforeProcessCleanup(t *testing.T) {
	for _, mode := range []string{"serve failure", "shutdown"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			worker := &testDeliveryWorker{started: make(chan struct{}), stopped: make(chan struct{})}
			retention := &testRetentionWorker{started: make(chan struct{}), stopped: make(chan struct{})}
			var order []string
			assembled := &realm{retention: retention, workers: []deliveryWorker{worker, nil}, resources: &resources{}}
			assembled.resources.add(func() {
				for _, stopped := range []chan struct{}{worker.stopped, retention.stopped} {
					select {
					case <-stopped:
					default:
						t.Error("realm client closed before workers joined")
					}
				}
				order = append(order, "realm clients")
			})
			owned := &resources{}
			owned.add(func() { order = append(order, "process dependencies") })
			owned.add(assembled.resources.close)
			failure := errors.New("serve failed")
			app := &App{resources: owned, serve: func(ctx context.Context) error {
				return assembled.run(ctx, zap.NewNop(), func(ctx context.Context) error {
					for _, started := range []chan struct{}{worker.started, retention.started} {
						select {
						case <-started:
						case <-ctx.Done():
							return ctx.Err()
						}
					}
					order = append(order, "server drained")
					if mode == "serve failure" {
						return failure
					}
					cancel()
					return nil
				})
			}}
			err := app.Run(ctx)
			app.Close()
			if mode == "serve failure" && !errors.Is(err, failure) || mode == "shutdown" && err != nil {
				t.Fatalf("unexpected lifecycle error: %v", err)
			}
			if !reflect.DeepEqual(order, []string{"server drained", "realm clients", "process dependencies"}) {
				t.Fatalf("wrong cleanup order: %v", order)
			}
		})
	}
}

func TestRealmCleanupDoesNotCloseProcess(t *testing.T) {
	processClosed := false
	owned := &resources{}
	owned.add(func() { processClosed = true })
	clients := &resources{}
	closed := 0
	clients.add(func() { closed++ })
	owned.add(clients.close)
	clients.close()
	if processClosed || closed != 1 {
		t.Fatal("realm cleanup closed borrowed dependencies")
	}
	owned.close()
	owned.close()
	if !processClosed || closed != 1 {
		t.Fatal("cleanup repeated or leaked an owner")
	}
}

func TestDisabledDeliveryIsNotScheduled(t *testing.T) {
	if workers := realmDeliveryWorkers(nil, nil, nil, nil); len(workers) != 0 {
		t.Fatal("nil delivery pointers became active interfaces")
	}
	recovery, account, mfa := &passwordservice.RecoveryService{}, &accountservice.Service{}, &mfaservice.RecoveryDelivery{}
	workers := realmDeliveryWorkers(recovery, account, mfa, nil)
	if len(workers) != 3 || workers[0] != recovery || workers[1] != account || workers[2] != mfa {
		t.Fatal("disabled email OTP delivery was scheduled or durable delivery was omitted")
	}
	email := &otpservice.Delivery{}
	workers = realmDeliveryWorkers(recovery, account, mfa, email)
	if len(workers) != 4 || workers[3] != email {
		t.Fatal("enabled email OTP delivery was omitted")
	}
}
