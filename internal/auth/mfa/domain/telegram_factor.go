package domain

import "time"

type TelegramFactor struct {
	Allowed    bool
	Configured bool
	BotID      int64
	TelegramID int64
	EnabledAt  *time.Time
}
