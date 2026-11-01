package domain

import "errors"

var ErrInvalidTelegramPreparation = errors.New("invalid Telegram channel preparation")

type TelegramBotBinding struct {
	ID            int64
	PolicyVersion int64
}

func (b TelegramBotBinding) Valid() bool { return ValidTelegramID(b.ID) && b.PolicyVersion > 0 }

func ValidTelegramID(id int64) bool { return id > 0 && id < 1<<52 }

func ValidTelegramCode(code string) bool {
	if len(code) != 8 {
		return false
	}
	for _, char := range code {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}
