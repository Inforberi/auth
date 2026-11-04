package runtime

import (
	"strconv"

	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	"github.com/Inforberi/financial-intelligence/internal/infra/mailer"
)

func MailConfig(c settingsdomain.SMTPConfig, password string) mailer.Config {
	return mailer.Config{
		SMTPHost: c.Host, SMTPPort: strconv.Itoa(c.Port), SMTPUsername: c.Username,
		SMTPPassword: password, SMTPFrom: c.From, SMTPDomain: c.Domain, RequireTLS: c.RequireTLS,
	}
}
