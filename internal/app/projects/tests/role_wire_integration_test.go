package projects_test

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
)

// Block the client's next socket read, without blocking the server's COMMIT.
// The controller observes the durable receipt before closing the actual socket.
type roleReplyGate struct {
	net.Conn
	armed   atomic.Bool
	entered chan struct{}
	closed  chan struct{}
	once    sync.Once
	notice  sync.Once
}

func (c *roleReplyGate) Read(p []byte) (int, error) {
	if c.armed.Load() {
		c.notice.Do(func() { close(c.entered) })
		timeout := time.NewTimer(2 * time.Second)
		defer timeout.Stop()
		select {
		case <-c.closed:
			return 0, net.ErrClosed
		case <-timeout.C:
			return 0, context.DeadlineExceeded
		}
	}
	return c.Conn.Read(p)
}

func (c *roleReplyGate) Close() error {
	var err error
	c.once.Do(func() {
		err = c.Conn.Close()
		close(c.closed)
	})
	return err
}

type roleWireDatabase struct {
	*pgx.Conn
	gate *roleReplyGate
}

func (db roleWireDatabase) BeginTx(ctx context.Context, options pgx.TxOptions) (pgx.Tx, error) {
	tx, err := db.Conn.BeginTx(ctx, options)
	if err != nil {
		return nil, err
	}
	return roleWireTransaction{Tx: tx, gate: db.gate}, nil
}

type roleWireTransaction struct {
	pgx.Tx
	gate *roleReplyGate
}

func (tx roleWireTransaction) Commit(ctx context.Context) error {
	tx.gate.armed.Store(true)
	return tx.Tx.Commit(ctx)
}
