package router

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/Inforberi/financial-intelligence/docs"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accounthttp "github.com/Inforberi/financial-intelligence/internal/auth/account/transport/http"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	passwordhttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/transport/http"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/logger"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/dev"
	requestmiddleware "github.com/Inforberi/financial-intelligence/internal/transport/http/middleware"
)

type apiSchema struct {
	Ref        string               `json:"$ref"`
	Type       string               `json:"type"`
	Properties map[string]apiSchema `json:"properties"`
	Required   []string             `json:"required"`
}

type apiOperation struct {
	Description string   `json:"description"`
	Consumes    []string `json:"consumes"`
	Produces    []string `json:"produces"`
	Parameters  []struct {
		In       string    `json:"in"`
		Required bool      `json:"required"`
		Schema   apiSchema `json:"schema"`
	} `json:"parameters"`
	Responses map[string]struct {
		Schema apiSchema `json:"schema"`
	} `json:"responses"`
}

type apiDocument struct {
	Version     string                             `json:"swagger"`
	BasePath    string                             `json:"basePath"`
	Paths       map[string]map[string]apiOperation `json:"paths"`
	Definitions map[string]apiSchema               `json:"definitions"`
}

func readAPI(t *testing.T) apiDocument {
	t.Helper()
	var doc apiDocument
	if err := json.Unmarshal([]byte(docs.SwaggerInfo.ReadDoc()), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Version != "2.0" || doc.BasePath != "/" {
		t.Fatal("unexpected API format/basePath")
	}
	return doc
}

func contractHandlers(env string) Handlers {
	log := zap.NewNop()
	return Handlers{
		Session:           sessionhttp.NewHandler(contractManagement{}, log),
		Recovery:          passwordhttp.NewRecovery(contractRecovery{}, log),
		Account:           accounthttp.New(contractAccounts{}, log),
		EmailChange:       accounthttp.NewEmailChange(contractEmailChange{}, log),
		ProtectedRecovery: passwordhttp.NewProtectedRecovery(contractProtectedRecovery{}, log),
		Config:            &config.Config{Logger: logger.Config{Env: env}, Browser: requestmiddleware.OriginConfig{AllowedOrigins: []string{"https://localhost:8443"}}},
		PasswordHandler:   passwordhttp.New(contractPasswords{}, log),
		Middleware:        sessionhttp.New(contractSessions{}, log),
		MailTest:          dev.NewMailTest(contractMail{}, log),
		ReadyCheck:        func(context.Context) error { return nil },
	}
}

type contractPasswords struct{}

func (contractPasswords) Register(context.Context, string, string, string, string) (*passwordservice.RegisterResult, error) {
	return &passwordservice.RegisterResult{UserID: "user-1", Token: "contract-token", ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func (contractPasswords) Login(context.Context, passwordservice.LoginInput) (*passwordservice.LoginResult, error) {
	return &passwordservice.LoginResult{UserID: "user-1", Token: "contract-token", ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func (contractPasswords) ChangePassword(context.Context, accountdomain.UserID, string, string, string) error {
	return nil
}

type contractSessions struct{}

func (contractSessions) ValidateSession(_ context.Context, token string) (*sessionservice.ValidationResult, error) {
	if token != "valid" {
		return nil, sessiondomain.ErrSessionNotFound
	}
	return &sessionservice.ValidationResult{UserID: "user-1", TokenHash: "hash", SessionID: currentSessionID}, nil
}

const currentSessionID = "11111111-1111-4111-8111-111111111111"

type contractManagement struct{}

func (contractManagement) List(context.Context, accountdomain.UserID, string, string) (*sessionservice.SessionPage, error) {
	return &sessionservice.SessionPage{Sessions: []sessiondomain.Session{{ID: currentSessionID}}}, nil
}

func (contractManagement) Revoke(context.Context, accountdomain.UserID, string, string) error {
	return nil
}

func (contractManagement) LogoutAll(context.Context, accountdomain.UserID, string) error { return nil }

type contractMail struct{}

func (contractMail) Send(string, string, string) error { return nil }

type contractAccounts struct{}

type contractRecovery struct{}

func (contractRecovery) Forgot(context.Context, string, string) error                { return nil }
func (contractRecovery) Reset(context.Context, string, string, string, string) error { return nil }

func (contractAccounts) AllowRegistration(context.Context, string) error { return nil }
func (contractAccounts) Resend(_ context.Context, email, _ string) error {
	_, err := accountdomain.NewEmail(email)
	return err
}
func (contractAccounts) Confirm(context.Context, string, string) error               { return nil }
func (contractAccounts) RequireVerified(context.Context, accountdomain.UserID) error { return nil }

type contractEmailChange struct{}

type contractProtectedRecovery struct{}

func (contractProtectedRecovery) Recover(context.Context, string, string, string, string) error {
	return nil
}

func (contractEmailChange) Request(context.Context, accountdomain.UserID, string, string, string, string) error {
	return nil
}
func (contractEmailChange) Confirm(context.Context, string, string) error { return nil }
func (contractEmailChange) Report(context.Context, string, string) error  { return nil }
