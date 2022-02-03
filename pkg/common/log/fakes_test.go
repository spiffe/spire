package log

import "context"

var (
	_ ReopenableWriteCloser = (*cancelingReopenableFile)(nil)
	_ Reopener              = (*fakeReopenerError)(nil)
)

type cancelingReopenableFile struct {
	rf     *ReopenableFile
	cancel context.CancelFunc
}

type fakeReopenerError struct {
	err error
}

func (c *cancelingReopenableFile) Reopen() error {
	err := c.rf.Reopen()
	c.cancel()
	return err
}

func (c *cancelingReopenableFile) Write(b []byte) (n int, err error) {
	return c.rf.Write(b)
}

func (c *cancelingReopenableFile) Close() error {
	return c.rf.Close()
}

func (f *fakeReopenerError) Reopen() error {
	if f.err != nil {
		return f.err
	}
	return nil
}
