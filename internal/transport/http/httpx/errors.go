package httpx

import (
	"errors"
	"net/http"

	"go.uber.org/zap"

	"github.com/Inforberi/financial-intelligence/internal/infra/logger"
)

type Failure struct {
	Status  int
	Code    string
	Message string
	Headers http.Header
}

type ErrorRule struct {
	Target   error
	Match    func(error) bool
	Response Failure
}

func MatchError(target error, status int, code, message string) ErrorRule {
	return ErrorRule{Target: target, Response: Failure{Status: status, Code: code, Message: message}}
}

// Rules are ordered: the first match wins, including for joined errors.
func MapError(err error, rules []ErrorRule, fallback Failure) Failure {
	for _, rule := range rules {
		if (rule.Target != nil && errors.Is(err, rule.Target)) || (rule.Match != nil && rule.Match(err)) {
			return rule.Response
		}
	}
	return fallback
}

func WriteFailure(w http.ResponseWriter, failure Failure) {
	for name, values := range failure.Headers {
		w.Header().Del(name)
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	Error(w, failure.Status, failure.Code, failure.Message)
}

func RespondError(w http.ResponseWriter, r *http.Request, log *zap.Logger, operation string, err error, rules []ErrorRule, fallback Failure) {
	failure := MapError(err, rules, fallback)
	requestLog := logger.FromContext(r.Context(), log)
	if requestLog != nil {
		fields := []zap.Field{
			zap.String("operation", operation),
			zap.String("error_code", failure.Code),
			zap.Int("status", failure.Status),
		}
		// Dependency errors may carry passwords, tokens, DSNs or provider responses.
		if failure.Status >= http.StatusInternalServerError {
			requestLog.Error("request failed", fields...)
		} else {
			requestLog.Warn("request rejected", fields...)
		}
	}
	WriteFailure(w, failure)
}
