package service

import "context"

type loginLimiter interface {
	Allow(context.Context, string, string) error
}

type PasswordService struct {
	repo       passwordRepo
	session    session
	hash       hasher
	loginLimit loginLimiter
}

func New(repo passwordRepo, session session, hash hasher, limit loginLimiter) *PasswordService {
	return &PasswordService{repo: repo, session: session, hash: hash, loginLimit: limit}
}
