package service

type SessionService struct {
	now   clock
	repo  sessionRepo
	token tokenManager
	cfg   Config
}

func New(now clock, repo sessionRepo, token tokenManager, cfg Config) *SessionService {
	return &SessionService{
		now:   now,
		repo:  repo,
		token: token,
		cfg:   cfg,
	}
}
