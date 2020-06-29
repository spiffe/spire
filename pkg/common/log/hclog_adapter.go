package log

import (
	"bytes"
	"io"
	"log"
	"os"

	"github.com/hashicorp/go-hclog"
	"github.com/sirupsen/logrus"
)

// HCLogAdapter implements the hclog interface, and wraps it
// around a Logrus entry
type HCLogAdapter struct {
	log  logrus.FieldLogger
	name string
	args []interface{} // key/value pairs if this logger was created via With()
}

func NewHCLogAdapter(log logrus.FieldLogger, name string) *HCLogAdapter {
	return &HCLogAdapter{
		log:  log,
		name: name,
	}
}

// HCLog has one more level than we do. As such, we will never
// set trace level.
func (*HCLogAdapter) Trace(_ string, _ ...interface{}) {
}

func (a *HCLogAdapter) Debug(msg string, args ...interface{}) {
	a.CreateEntry(args).Debug(msg)
}

func (a *HCLogAdapter) Info(msg string, args ...interface{}) {
	a.CreateEntry(args).Info(msg)
}

func (a *HCLogAdapter) Warn(msg string, args ...interface{}) {
	a.CreateEntry(args).Warn(msg)
}

func (a *HCLogAdapter) Error(msg string, args ...interface{}) {
	a.CreateEntry(args).Error(msg)
}

func (a *HCLogAdapter) Log(level hclog.Level, msg string, args ...interface{}) {
	switch level {
	case hclog.Trace:
		a.Trace(msg, args...)
	case hclog.Debug:
		a.Debug(msg, args...)
	case hclog.Info:
		a.Info(msg, args...)
	case hclog.Warn:
		a.Warn(msg, args...)
	case hclog.Error:
		a.Error(msg, args...)
	}
}

func (a *HCLogAdapter) IsTrace() bool {
	return false
}

func (a *HCLogAdapter) IsDebug() bool {
	return a.shouldEmit(logrus.DebugLevel)
}

func (a *HCLogAdapter) IsInfo() bool {
	return a.shouldEmit(logrus.InfoLevel)
}

func (a *HCLogAdapter) IsWarn() bool {
	return a.shouldEmit(logrus.WarnLevel)
}

func (a *HCLogAdapter) IsError() bool {
	return a.shouldEmit(logrus.ErrorLevel)
}

func (a *HCLogAdapter) SetLevel(hclog.Level) {
	// interface definition says it is ok for this to be a noop if
	// implementations don't need/want to support dynamic level changing, which
	// we don't currently.
}

func (a *HCLogAdapter) With(args ...interface{}) hclog.Logger {
	e := a.CreateEntry(args)
	newArgs := make([]interface{}, len(a.args)+len(args))
	copy(newArgs, a.args)
	copy(newArgs[len(a.args):], args)
	return &HCLogAdapter{
		log:  e,
		args: newArgs,
	}
}

// ImpliedArgs returns With key/value pairs
func (a *HCLogAdapter) ImpliedArgs() []interface{} {
	return a.args
}

func (a *HCLogAdapter) Name() string {
	return a.name
}

func (a *HCLogAdapter) Named(name string) hclog.Logger {
	var newName bytes.Buffer
	if a.name != "" {
		newName.WriteString(a.name)
		newName.WriteString(".")
	}
	newName.WriteString(name)

	return a.ResetNamed(newName.String())
}

func (a *HCLogAdapter) ResetNamed(name string) hclog.Logger {
	fields := []interface{}{"subsystem_name", name}
	e := a.CreateEntry(fields)
	return &HCLogAdapter{log: e, name: name}
}

// StandardLogger is meant to return a stdlib Logger type which wraps around
// hclog. It does this by providing an io.Writer and instantiating a new
// Logger. It then tries to interpret the log level by parsing the message.
//
// Since we are not using `hclog` in a generic way, and I cannot find any
// calls to this method from go-plugin, we will poorly support this method.
// Rather than pull in all of hclog writer parsing logic, pass it a Logrus
// writer, and hardcode the level to INFO.
//
// Apologies to those who find themselves here.
func (a *HCLogAdapter) StandardLogger(opts *hclog.StandardLoggerOptions) *log.Logger {
	entry := a.log.WithFields(logrus.Fields{})
	return log.New(entry.WriterLevel(logrus.InfoLevel), "", 0)
}

func (a *HCLogAdapter) StandardWriter(opts *hclog.StandardLoggerOptions) io.Writer {
	var w io.Writer
	logger, ok := a.log.(*logrus.Logger)
	if ok {
		w = logger.Out
	}
	if w == nil {
		w = os.Stderr
	}
	return w
}

func (a *HCLogAdapter) shouldEmit(level logrus.Level) bool {
	return a.log.WithFields(logrus.Fields{}).Level >= level
}

func (a *HCLogAdapter) CreateEntry(args []interface{}) *logrus.Entry {
	if len(args)%2 != 0 {
		args = append(args, "<unknown>")
	}

	fields := make(logrus.Fields)
	for i := 0; i < len(args); i += 2 {
		k, ok := args[i].(string)
		if !ok {
			continue
		}
		v := args[i+1]
		fields[k] = v
	}

	return a.log.WithFields(fields)
}
