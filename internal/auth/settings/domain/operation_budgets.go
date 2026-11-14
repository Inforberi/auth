package domain

import "errors"

var ErrInvalidOperationBudgets = errors.New("invalid operation budgets")

type OperationBudgetsPolicy struct {
	GoogleIP         int `json:"googleIPPerMinute"`
	GoogleGlobal     int `json:"googleGlobalPerMinute"`
	TelegramIP       int `json:"telegramIPPerMinute"`
	TelegramGlobal   int `json:"telegramGlobalPerMinute"`
	MFAUser          int `json:"mfaUserPerMinute"`
	MFAIP            int `json:"mfaIPPerMinute"`
	MFAGlobal        int `json:"mfaGlobalPerMinute"`
	BindingRequest   int `json:"bindingRequestPerMinute"`
	BindingConfirm   int `json:"bindingConfirmPerMinute"`
	InvitationActor  int `json:"invitationActorPerMinute"`
	InvitationGlobal int `json:"invitationGlobalPerMinute"`
	ActivationGlobal int `json:"activationGlobalPerMinute"`
	TemporaryActor   int `json:"temporaryActorPerMinute"`
	TemporaryGlobal  int `json:"temporaryGlobalPerMinute"`
	TemporarySetup   int `json:"temporarySetupPerMinute"`
	JWTActor         int `json:"jwtActorPerMinute"`
	JWTSession       int `json:"jwtSessionPerMinute"`
	JWTIP            int `json:"jwtIPPerMinute"`
	JWTGlobal        int `json:"jwtGlobalPerMinute"`
	JWTConsumer      int `json:"jwtConsumerPerMinute"`
	JWTIntrospection int `json:"jwtIntrospectionPerMinute"`
}

func (p OperationBudgetsPolicy) Validate(ceiling OperationBudgetsPolicy) error {
	for _, limit := range [][3]int{
		{p.GoogleIP, ceiling.GoogleIP, 1},
		{p.GoogleGlobal, ceiling.GoogleGlobal, 1},
		{p.TelegramIP, ceiling.TelegramIP, 1},
		{p.TelegramGlobal, ceiling.TelegramGlobal, 1},
		{p.MFAUser, ceiling.MFAUser, 2},
		{p.MFAIP, ceiling.MFAIP, 2},
		{p.MFAGlobal, ceiling.MFAGlobal, 2},
		{p.BindingRequest, ceiling.BindingRequest, 1},
		{p.BindingConfirm, ceiling.BindingConfirm, 1},
		{p.InvitationActor, ceiling.InvitationActor, 1},
		{p.InvitationGlobal, ceiling.InvitationGlobal, 1},
		{p.ActivationGlobal, ceiling.ActivationGlobal, 1},
		{p.TemporaryActor, ceiling.TemporaryActor, 1},
		{p.TemporaryGlobal, ceiling.TemporaryGlobal, 1},
		{p.TemporarySetup, ceiling.TemporarySetup, 1},
		{p.JWTActor, ceiling.JWTActor, 1},
		{p.JWTSession, ceiling.JWTSession, 1},
		{p.JWTIP, ceiling.JWTIP, 1},
		{p.JWTGlobal, ceiling.JWTGlobal, 1},
		{p.JWTConsumer, ceiling.JWTConsumer, 1},
		{p.JWTIntrospection, ceiling.JWTIntrospection, 1},
	} {
		if limit[0] < limit[2] || limit[0] > limit[1] {
			return ErrInvalidOperationBudgets
		}
	}
	return nil
}
