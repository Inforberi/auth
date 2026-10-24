package admission

import "errors"

var (
	ErrBusy        = errors.New("platform operation capacity exhausted")
	ErrRateLimited = errors.New("platform operation rate limited")
	ErrUnavailable = errors.New("platform operation admission unavailable")
)

type Config struct {
	MaxInFlight        int `env:"PLATFORM_OPERATIONS_MAX_IN_FLIGHT" env-default:"8"`
	PerActorInFlight   int `env:"PLATFORM_OPERATIONS_ACTOR_MAX_IN_FLIGHT" env-default:"2"`
	PerProjectInFlight int `env:"PLATFORM_OPERATIONS_PROJECT_MAX_IN_FLIGHT" env-default:"2"`
	ActorPerMinute     int `env:"PLATFORM_OPERATIONS_ACTOR_PER_MINUTE" env-default:"120"`
	ProjectPerMinute   int `env:"PLATFORM_OPERATIONS_PROJECT_PER_MINUTE" env-default:"120"`
	GlobalPerMinute    int `env:"PLATFORM_OPERATIONS_GLOBAL_PER_MINUTE" env-default:"600"`
}

func DefaultConfig() Config {
	return Config{
		MaxInFlight: 8, PerActorInFlight: 2, PerProjectInFlight: 2,
		ActorPerMinute: 120, ProjectPerMinute: 120, GlobalPerMinute: 600,
	}
}

func (c Config) Validate() error {
	if c.MaxInFlight < 1 || c.MaxInFlight > 1000 || c.PerActorInFlight < 1 || c.PerActorInFlight > c.MaxInFlight || c.PerProjectInFlight < 1 || c.PerProjectInFlight > c.MaxInFlight {
		return errors.New("platform operation concurrency requires positive bounded global/actor/project caps")
	}
	if c.GlobalPerMinute < 2 || c.GlobalPerMinute > 1_000_000 || c.ActorPerMinute < 1 || c.ActorPerMinute >= c.GlobalPerMinute || c.ProjectPerMinute < 1 || c.ProjectPerMinute >= c.GlobalPerMinute {
		return errors.New("platform operation minute budgets require actor/project limits below the global limit")
	}
	return nil
}
