package native

import (
	"time"

	projectmfa "github.com/Inforberi/financial-intelligence/internal/app/projects/mfa"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
)

func (p *ProjectTokens) NativeAvailable() bool { return p.native != nil }

func (p *ProjectTokens) NativePasswordEnabled() bool {
	return p.native != nil && p.cfg.Native.PasswordEnabled
}

func (p *ProjectTokens) NativeFactory() *projectmfa.ProjectMFALogin {
	if p.native == nil {
		return nil
	}
	return p.native.mfa
}

func (p *ProjectTokens) NativeEmailMFA() *projectmfa.ProjectEmailMFA {
	if p.native == nil {
		return nil
	}
	return p.native.emailMFA
}

func (p *ProjectTokens) BindEmailMFA(email *projectmfa.ProjectEmailMFA, timeout time.Duration) {
	p.native.emailMFA = email.WithRuntime(projectmfa.BindProjectMFA(p.native.mfa, p.key, p.deps.Registry, p.deps.Reader, timeout, false))
}

func (p *ProjectTokens) SessionPolicy() (sessionservice.Config, bool) {
	if p.cfg.Tokens.Native == nil {
		return sessionservice.Config{}, false
	}
	return p.cfg.Tokens.Native.Sessions, true
}
