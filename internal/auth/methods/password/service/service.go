package service

type PasswordService struct {
	repo    passwordRepo
	session session
	hash    hasher
}

func New(repo passwordRepo, session session, hash hasher) *PasswordService {
	return &PasswordService{repo: repo, session: session, hash: hash}
}
