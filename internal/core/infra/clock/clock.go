package clock

import "time"

type UTCClock struct{}

func (UTCClock) NowUTC() time.Time {
	return time.Now().UTC()
}
