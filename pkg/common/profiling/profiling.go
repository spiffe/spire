package profiling

import (
	"errors"
	"os"
	"sync"
	"time"

	"gopkg.in/tomb.v2"
)

type Config struct {
	// Used to tag the profile in some manner. Its meaning depends on how it is used
	// by the dumpers implementations.
	Tag string
	// Number of seconds that have to elapse between profiles generation. In other words,
	// each time Frequency seconds elapse, a profiling tick happens and hence the profiles
	// generation.
	Frequency int
	// DebugLevel is used as the second parameter when calling profile.WriteTo to write
	// a profile. NOTE: This affects the format of the profiling output.
	DebugLevel int
	// If true, runs the garbage collector before writing a "heap" profile.
	RunGCBeforeHeapProfile bool
	// Profiles is an array of the names of the profiles that will get generated on
	// each profiling tick.
	// Available values for each element:
	// "goroutine", "threadcreate", "heap", "block", "mutex", "trace", "cpu"
	Profiles []string
}

// Dumper defines the interface that are used to dump profiling data of some kind.
type Dumper interface {
	// Prepares the Dumper before any profiling tick takes place.
	Prepare() error
	// Dumps the profiling data to some destination.
	// timestamp - string containing the time where the profiling tick begun executing,
	//             in the format yyyy-MM-dd_mmhhss.
	// config - configuration used to start the profiling component.
	// name - name of the profile that is currently dumping data.
	Dump(timestamp string, config *Config, name string) error
	// Releases any resources associated with this Dumper.
	Release() error
}

type profiler struct {
	c      *Config
	t      *tomb.Tomb
	ticker *time.Ticker
}

const (
	profilesDir = ".profiles"
)

var (
	prof               *profiler
	profM              = &sync.Mutex{}
	profileDumper      = &dumper{}
	heapProfileDumper  = &heapDumper{profileDumper}
	cpuProfileDumper   = &cpuDumper{}
	traceProfileDumper = &traceDumper{}
	dumpers            = map[string]Dumper{
		"goroutine":    profileDumper,
		"threadcreate": profileDumper,
		"heap":         heapProfileDumper,
		"block":        profileDumper,
		"mutex":        profileDumper,
		"trace":        traceProfileDumper,
		"cpu":          cpuProfileDumper,
	}

	ErrProfilerAlreadyStarted = errors.New("profiler already started")
	ErrUnknownProfile         = errors.New("unknown profile")
)

// Start profiling
func Start(conf *Config) error {
	profM.Lock()
	defer profM.Unlock()

	if prof == nil {
		err := createProfilesFolder()
		if err != nil {
			return err
		}

		prof = &profiler{
			c:      conf,
			t:      &tomb.Tomb{},
			ticker: time.NewTicker(time.Duration(conf.Frequency) * time.Second),
		}

		prof.t.Go(prof.run)
	} else {
		return ErrProfilerAlreadyStarted
	}
	return nil
}

// Stop stops profiling and releases resources.
func Stop() {
	profM.Lock()
	defer profM.Unlock()

	if prof != nil {
		prof.t.Kill(nil)
		<-prof.t.Dead()
	}
}

func (p *profiler) run() error {
	p.prepareDumpers()
	for {
		select {
		case <-p.ticker.C:
			p.dumpProfiles()
		case <-p.t.Dying():
			p.ticker.Stop()
			p.releaseDumpers()
			return nil
		}
	}
}

func (p *profiler) prepareDumpers() {
	for _, name := range p.c.Profiles {
		if dumper, ok := dumpers[name]; ok {
			err := dumper.Prepare()
			if err != nil {
				// TODO: remove dumper name from p.c.Profiles
			}
		}
	}
}

func (p *profiler) dumpProfiles() {
	now := time.Now().Format("2006-01-02_150405")
	for _, name := range p.c.Profiles {
		if dumper, ok := dumpers[name]; ok {
			dumper.Dump(now, p.c, name)
		}
	}
}

func (p *profiler) releaseDumpers() {
	for _, name := range p.c.Profiles {
		if dumper, ok := dumpers[name]; ok {
			dumper.Release()
		}
	}
}

func createProfilesFolder() error {
	return os.MkdirAll(profilesDir, os.ModePerm)
}
