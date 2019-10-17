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
	c *Config
}

type heapDumper struct {
	dumper *dumper
}

type cpuDumper struct {
	c    *Config
	data *os.File
}

type traceDumper struct {
	c    *Config
	data *os.File
}

func (d *dumper) Prepare() error {
	err := createProfilesFolder()
	if err != nil {
		return err
	}
	return nil
}

func (d *dumper) Dump(timestamp string, name string) error {
	profile := pprof.Lookup(name)
	if profile == nil {
		return ErrUnknownProfile
	}

	filename := getFilename(timestamp, d.c.Tag, name)
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	return profile.WriteTo(f, d.c.DebugLevel)
}

func (d *dumper) Release() error {
	// Do nothing
	return nil
}

func (d *heapDumper) Prepare() error {
	return d.dumper.Prepare()
}

func (d *heapDumper) Dump(timestamp string, name string) error {
	if d.dumper.c.RunGCBeforeHeapProfile {
		runtime.GC()
	}
	return d.dumper.Dump(timestamp, name)
}

func (d *heapDumper) Release() error {
	return d.dumper.Release()
}

func (d *traceDumper) Prepare() error {
	err := createProfilesFolder()
	if err != nil {
		return err
	}
	f, err := os.Create(getTempFilename(d.c.Tag, traceProfTmpFilename))
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

func (d *traceDumper) Dump(timestamp string, name string) error {
	trace.Stop()
	d.data.Close()
	filename := getFilename(timestamp, d.c.Tag, name)
	os.Rename(getTempFilename(d.c.Tag, traceProfTmpFilename), filename)
	return d.Prepare()
}

func (d *traceDumper) Release() error {
	d.data.Close()
	os.Remove(getTempFilename(d.c.Tag, traceProfTmpFilename))
	return nil
}

func (d *cpuDumper) Prepare() error {
	err := createProfilesFolder()
	if err != nil {
		return err
	}
	f, err := os.Create(getTempFilename(d.c.Tag, cpuProfTmpFilename))
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

func (d *cpuDumper) Dump(timestamp string, name string) error {
	pprof.StopCPUProfile()
	d.data.Close()
	filename := getFilename(timestamp, d.c.Tag, name)
	os.Rename(getTempFilename(d.c.Tag, cpuProfTmpFilename), filename)
	return d.Prepare()
}

func (d *cpuDumper) Release() error {
	d.data.Close()
	os.Remove(getTempFilename(d.c.Tag, cpuProfTmpFilename))
	return nil
}

func getTempFilename(tag, name string) string {
	filename := &strings.Builder{}
	filename.WriteString(profilesDir)
	filename.WriteString("/")
	filename.WriteString(tag)
	filename.WriteString("_")
	filename.WriteString(name)
	return filename.String()
}

func getFilename(timestamp, tag, name string) string {
	filename := &strings.Builder{}
	filename.WriteString(profilesDir)
	filename.WriteString("/")
	filename.WriteString(timestamp)
	filename.WriteString("_")
	filename.WriteString(tag)
	filename.WriteString("_")
	filename.WriteString(name)
	filename.WriteString(".pb.gz")
	return filename.String()
}

func createProfilesFolder() error {
	return os.MkdirAll(profilesDir, os.ModePerm)
}
