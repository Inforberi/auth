package service

import "context"

type loginLimiter interface {
	Allow(context.Context, string, string) error
}

type PasswordService struct {
	repo        passwordRepo
	session     session
	hash        loginHasher
	loginLimit  loginLimiter
	checkPolicy func(context.Context, bool) error
}

func New(repo passwordRepo, session session, hash loginHasher, limit loginLimiter) *PasswordService {
	return &PasswordService{repo: repo, session: session, hash: hash, loginLimit: limit}
}

// WithPublicPolicy adds early admission; repository commit checks remain mandatory.
func (s *PasswordService) WithPublicPolicy(check func(context.Context, bool) error) *PasswordService {
	s.checkPolicy = check
	return s
}
