package uptime

import "time"

var start = time.Now()

func Uptime() time.Duration {
	return time.Since(start)
}
