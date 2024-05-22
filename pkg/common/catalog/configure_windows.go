package catalog

import "context"

func ReconfigureOnSignal(ctx context.Context, reconfigurer Reconfigurer) error {
	// TODO: maybe drive this using an event?
	<-ctx.Done()
	return ctx.Err()
}
