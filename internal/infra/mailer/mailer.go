package mailer

import "context"

type Mailer struct {
	cfg    Config
	source func(context.Context) (Config, error)
}

func NewWithSource(source func(context.Context) (Config, error)) *Mailer {
	return &Mailer{source: source}
}

func New(cfg Config) *Mailer {
	return &Mailer{cfg: cfg}
}
