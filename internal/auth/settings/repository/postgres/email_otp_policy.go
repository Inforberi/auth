package postgres

import otp "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"

func (r *Repository) EmailOTPPolicy() VersionedPolicy[otp.Policy] {
	return VersionedPolicy[otp.Policy]{repo: r, table: emailOTPPolicyTable}
}
