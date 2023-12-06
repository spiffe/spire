package agent

import (
	"fmt"
	"time"
)

func validate(s string) error {
	if len(s) < 10 {
		return fmt.Errorf("date is too short")
	}
	if len(s) > 10 {
		return fmt.Errorf("date is too long")
	}
	_, err := time.Parse("2006-01-02", s)
	if err != nil {
		return err
	}
	return nil
}
