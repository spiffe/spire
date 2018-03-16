package profiling

import (
	"os"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"strings"
)

const (
	cpuProfTmpFilename   = "current_cpu_profile"
	traceProfTmpFilename = "current_trace_profile"
)

type dumper struct {
}

type heapDumper struct {
	dumper *dumper
}

type cpuDumper struct {
	data *os.File
}

type traceDumper struct {
	data *os.File
}

func (d *dumper) Prepare() error {
	// Do nothing
	return nil
}

func (d *dumper) Dump(timestamp string, config *Config, name string) error {
	profile := pprof.Lookup(name)
	if profile == nil {
		return ErrUnknownProfile
	}

	filename := getFilename(timestamp, name)
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	return profile.WriteTo(f, config.DebugLevel)
}

func (d *dumper) Release() error {
	// Do nothing
	return nil
}

func (d *heapDumper) Prepare() error {
	return d.dumper.Prepare()
}

func (d *heapDumper) Dump(timestamp string, config *Config, name string) error {
	if config.RunGCBeforeHeapProfile {
		runtime.GC()
	}
	return d.dumper.Dump(timestamp, config, name)
}

func (d *heapDumper) Release() error {
	return d.dumper.Release()
}

func (d *traceDumper) Prepare() error {
	f, err := os.Create(getTempFilename(traceProfTmpFilename))
	if err != nil {
		return err
	}
	d.data = f
	err = trace.Start(d.data)
	if err != nil {
		return err
	}
	return nil
}

func (d *traceDumper) Dump(timestamp string, config *Config, name string) error {
	trace.Stop()
	d.data.Close()
	filename := getFilename(timestamp, name)
	os.Rename(getTempFilename(traceProfTmpFilename), filename)
	return d.Prepare()
}

func (d *traceDumper) Release() error {
	d.data.Close()
	os.Remove(getTempFilename(traceProfTmpFilename))
	return nil
}

func (d *cpuDumper) Prepare() error {
	f, err := os.Create(getTempFilename(cpuProfTmpFilename))
	if err != nil {
		return err
	}
	d.data = f
	err = pprof.StartCPUProfile(d.data)
	if err != nil {
		d.data.Close()
		return err
	}
	return nil
}

func (d *cpuDumper) Dump(timestamp string, config *Config, name string) error {
	pprof.StopCPUProfile()
	d.data.Close()
	filename := getFilename(timestamp, name)
	os.Rename(getTempFilename(cpuProfTmpFilename), filename)
	return d.Prepare()
}

func (d *cpuDumper) Release() error {
	d.data.Close()
	os.Remove(getTempFilename(cpuProfTmpFilename))
	return nil
}

func getTempFilename(name string) string {
	filename := &strings.Builder{}
	filename.WriteString(profilesDir)
	filename.WriteString("/")
	filename.WriteString(name)
	return filename.String()
}

func getFilename(timestamp string, name string) string {
	filename := &strings.Builder{}
	filename.WriteString(profilesDir)
	filename.WriteString("/")
	filename.WriteString(timestamp)
	filename.WriteString("_")
	filename.WriteString(name)
	filename.WriteString(".pb.gz")
	return filename.String()
}
