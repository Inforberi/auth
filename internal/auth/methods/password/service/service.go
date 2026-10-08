package service

type PasswordService struct {
	repo    passwordRepo
	session session
	hash    hasher
	now     clock
	tm      tokenManager
	redis   redisRepo
	cfg     Config
	mailer  mailer
}

func New(repo passwordRepo, session session, hash hasher, now clock, tm tokenManager, redis redisRepo, cfg Config, mailer mailer) *PasswordService {
	return &PasswordService{
		repo:    repo,
		session: session,
		hash:    hash,
		now:     now,
		tm:      tm,
		redis:   redis,
		cfg:     cfg,
		mailer:  mailer,
	}
}
