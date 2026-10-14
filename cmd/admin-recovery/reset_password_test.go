package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
)

type commandRecovery struct {
	calls    int
	err      error
	password []byte
	request  passworddomain.OperatorRecovery
}

func (f *commandRecovery) Preview(context.Context, accountdomain.UserID) (*passwordservice.OperatorRecoveryTarget, error) {
	return &passwordservice.OperatorRecoveryTarget{Database: "auth", Operator: "recovery_login", Status: "blocked", AuthVersion: 7}, nil
}

func (f *commandRecovery) Reset(_ context.Context, request passworddomain.OperatorRecovery, password []byte) (int64, error) {
	f.calls++
	f.request = request
	f.password = password
	return 8, f.err
}

func TestRecoveryCommand(t *testing.T) {
	const user = "11111111-1111-4111-8111-111111111111"
	for _, mode := range []string{"ok", "cancel", "old-confirmation", "pipe", "sql-error", "stale", "denied"} {
		t.Run(mode, func(t *testing.T) {
			opts := options{environment: "test", user: user, reason: "INC-123"}
			f := &commandRecovery{}
			input := "RESET test 127.0.0.1:5432/auth " + user + " v7\n"
			if mode == "cancel" {
				input = "no\n"
			}
			if mode == "old-confirmation" {
				input = "RESET test 127.0.0.1:5432/auth " + user + " v6\n"
			}
			if mode == "sql-error" {
				f.err = errors.New("postgres://credential-secret@private")
			}
			if mode == "stale" {
				f.err = passworddomain.ErrOperatorRecoveryConflict
			}
			if mode == "denied" {
				f.err = passworddomain.ErrOperatorRecoveryDenied
			}
			password := []byte("Syntheticpassword1")
			reads := 0
			var output bytes.Buffer
			err := execute(context.Background(), opts, "127.0.0.1:5432", f, strings.NewReader(input), &output, func() ([]byte, error) {
				reads++
				if mode == "pipe" {
					return nil, errors.New("secret input")
				}
				return password, nil
			})
			if (mode == "ok") != (err == nil) {
				t.Fatal(err)
			}
			if mode == "cancel" || mode == "old-confirmation" {
				if reads != 0 || f.calls != 0 {
					t.Fatal("read secret before confirmation")
				}
			} else if mode != "pipe" {
				if f.calls != 1 || f.request.ExpectedVersion != 7 || !bytes.Equal(password, make([]byte, len(password))) {
					t.Fatal("wrong mutation or secret not cleared")
				}
			}
			if strings.Contains(output.String(), "Syntheticpassword1") || (err != nil && strings.Contains(err.Error(), "credential-secret")) {
				t.Fatal("leaked secret")
			}
		})
	}
}

func TestRecoveryConnectionConfig(t *testing.T) {
	for _, tc := range []struct {
		url, env string
		ok       bool
	}{
		{"postgres://operator:synthetic@127.0.0.1:5432/auth?sslmode=disable", "test", true},
		{"postgres://operator:synthetic@db.example.test/auth?sslmode=verify-full", "prod", true},
		{"postgres://operator:synthetic@db.example.test/auth?sslmode=require", "prod", false},
		{"postgres://operator:synthetic@db.example.test/auth?sslmode=disable", "dev", false},
		{"postgres://operator:synthetic@127.0.0.1/auth?sslmode=disable&host=db.example.test", "test", false},
		{"postgres://operator:synthetic@127.0.0.1/auth?sslmode=disable&host=127.0.0.1,db.example.test", "test", false},
		{"", "prod", false},
		{"postgres://operator:synthetic@127.0.0.1/auth?sslmode=disable", "unknown", false},
	} {
		cfg, _, err := connectionConfig(tc.url, tc.env)
		if tc.ok != (err == nil) {
			t.Fatal(tc.env, err)
		}
		if err == nil && (cfg.MaxConns != 1 || cfg.MinConns != 0) {
			t.Fatal("unbounded command pool")
		}
		if err != nil && strings.Contains(err.Error(), "synthetic") {
			t.Fatal("DSN leak")
		}
	}
}
