package delivery

import (
	"context"
	"time"
)

// Run paces a mail queue; each tick stops at the first empty claim or after ten jobs.
func Run(ctx context.Context, process func(context.Context) (bool, error), report func(error)) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for range 10 {
				processed, err := process(ctx)
				if err != nil && ctx.Err() == nil {
					report(err)
				}
				if !processed || ctx.Err() != nil {
					break
				}
			}
		}
	}
}
