package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingstelegram "github.com/Inforberi/financial-intelligence/internal/auth/settings/telegram/service"
)

const telegramBotColumns = `m.version,COALESCE(m.telegram_bot_id,0),
 COALESCE(CASE WHEN b.bot_id=m.telegram_bot_id THEN b.username END,''),
 COALESCE(b.bot_id=m.telegram_bot_id,false),COALESCE(b.bot_id=m.telegram_bot_id,false)`

const telegramBotEncryptedColumns = `,b.token,b.webhook_secret,COALESCE(b.bot_id,0)`

const telegramBotFrom = ` FROM auth.mfa_settings m
 LEFT JOIN auth.telegram_bot_settings b ON b.singleton=m.singleton WHERE m.singleton`

func scanTelegramBot(row pgx.Row, secrets bool) (settingstelegram.TelegramBotStored, error) {
	var stored settingstelegram.TelegramBotStored
	values := []any{&stored.Version, &stored.BotID, &stored.Username, &stored.TokenSet, &stored.WebhookSecretSet}
	if secrets {
		values = append(values, &stored.Token, &stored.Webhook, &stored.StoredBotID)
	}
	err := row.Scan(values...)
	if errors.Is(err, pgx.ErrNoRows) {
		return stored, domain.ErrNotInitialized
	}
	return stored, err
}

func (r *Repository) ReadTelegramBot(ctx context.Context, actor accessservice.Principal) (domain.TelegramBotSnapshot, error) {
	stored, err := scanTelegramBot(r.db.QueryRow(ctx, `SELECT `+telegramBotColumns+telegramBotFrom+` AND `+settingsReadGuard,
		actor.UserID, actor.TokenHash, settings.AuthSettingsManage), false)
	if errors.Is(err, domain.ErrNotInitialized) {
		return domain.TelegramBotSnapshot{}, accessdomain.ErrForbidden
	}
	return stored.TelegramBotSnapshot, err
}

func (r *Repository) LoadTelegramBot(ctx context.Context) (settingstelegram.TelegramBotStored, error) {
	return scanTelegramBot(r.db.QueryRow(ctx, `SELECT `+telegramBotColumns+telegramBotEncryptedColumns+telegramBotFrom), true)
}

func ReadTelegramBotInTransaction(ctx context.Context, tx pgx.Tx, secrets bool) (settingstelegram.TelegramBotStored, error) {
	if secrets {
		return scanTelegramBot(tx.QueryRow(ctx, `SELECT `+telegramBotColumns+telegramBotEncryptedColumns+telegramBotFrom), true)
	}
	return scanTelegramBot(tx.QueryRow(ctx, `SELECT `+telegramBotColumns+telegramBotFrom), false)
}
