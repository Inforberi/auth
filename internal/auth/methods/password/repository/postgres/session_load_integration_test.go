package postgres

import (
	"context"
	"errors"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	sessionpostgres "github.com/Inforberi/financial-intelligence/internal/auth/session/repository/postgres"
)

func checkSessionReadLoad(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	t.Helper()
	rows, err := db.Query(ctx, `SELECT token_hash FROM auth.sessions ORDER BY token_hash LIMIT 100`)
	if err != nil {
		t.Fatal(err)
	}
	var tokens []string
	for rows.Next() {
		var token string
		if err := rows.Scan(&token); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		tokens = append(tokens, token)
	}
	rows.Close()
	if err := rows.Err(); err != nil || len(tokens) != 100 {
		t.Fatal("missing load fixture", err)
	}
	repo := sessionpostgres.New(db)
	const requests = 2000
	jobs := make(chan string, requests)
	latencies := make(chan time.Duration, requests)
	for i := range requests {
		jobs <- tokens[i%len(tokens)]
	}
	close(jobs)
	start := time.Now()
	var workers sync.WaitGroup
	for range 32 {
		workers.Go(func() {
			for token := range jobs {
				begin := time.Now()
				if _, err := repo.FindSession(ctx, token); err != nil {
					t.Error("validation failed under load", err)
				}
				latencies <- time.Since(begin)
			}
		})
	}
	workers.Wait()
	elapsed := time.Since(start)
	close(latencies)
	var samples []time.Duration
	for latency := range latencies {
		samples = append(samples, latency)
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	t.Logf("SQL-only session validation: %d reads, 32 callers, 10 connections, %.0f reads/s, p95=%s p99=%s", requests, float64(requests)/elapsed.Seconds(), samples[requests*95/100], samples[requests*99/100])
	if _, err := db.Exec(ctx, `UPDATE auth.users SET auth_version=auth_version+1
		WHERE id=(SELECT user_id FROM auth.sessions WHERE token_hash=$1)`, tokens[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.FindSession(ctx, tokens[0]); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
		t.Fatal("load bypassed durable revocation", err)
	}
}
