package profiling

import (
	"errors"
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
	// name - name of the profile that is currently dumping data.
	Dump(timestamp string, name string) error
	// Releases any resources associated with this Dumper.
	Release() error
}

type profiler struct {
	c       *Config
	dumpers map[string]Dumper
	t       *tomb.Tomb
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
	ErrNoDumpersActive        = errors.New("there are no dumpers active")
)

// OverrideDumper overrides the implementation for the dumper which has
// the specified profile name. This method must be called before calling Start() to
// take effect.
// Valid values for name are:
// "goroutine", "threadcreate", "heap", "block", "mutex", "trace" and "cpu".
func OverrideDumper(name string, dumper Dumper) error {
	profM.Lock()
	defer profM.Unlock()

	if _, ok := dumpers[name]; ok {
		dumpers[name] = dumper
		return nil
	}
	return ErrUnknownProfile
}

// Start profiling
func Start(conf *Config) error {
	profM.Lock()
	defer profM.Unlock()

	if prof == nil {
		configureDefaultDumpers(conf)

		prof = &profiler{
			c:       conf,
			dumpers: getDumpers(conf.Profiles),
			t:       &tomb.Tomb{},
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

// getDumpers returns a map of valid dumpers, it filters out any non existent profile name.
func getDumpers(profiles []string) map[string]Dumper {
	result := map[string]Dumper{}
	for _, name := range profiles {
		if dumper, ok := dumpers[name]; ok {
			result[name] = dumper
		}
	}
	return result
}

func (p *profiler) run() error {
	p.prepareDumpers()
	if len(p.dumpers) == 0 {
		return ErrNoDumpersActive
	}

	ticker := time.NewTicker(time.Duration(p.c.Frequency) * time.Second)
	for {
		select {
		case <-ticker.C:
			p.dumpProfiles()
		case <-p.t.Dying():
			ticker.Stop()
			p.releaseDumpers()
			return nil
		}
	}
}

func (p *profiler) prepareDumpers() {
	for name, dumper := range p.dumpers {
		err := dumper.Prepare()
		if err != nil {
			// Failed to prepare the dumper, delete it from valid dumpers.
			delete(p.dumpers, name)
		}
	}
}

func (p *profiler) dumpProfiles() {
	now := time.Now().Format("2006-01-02_150405")
	for name, dumper := range p.dumpers {
		dumper.Dump(now, name)
	}
}

func (p *profiler) releaseDumpers() {
	for _, dumper := range p.dumpers {
		dumper.Release()
	}
}

func configureDefaultDumpers(conf *Config) {
	profileDumper.c = conf
	heapProfileDumper.dumper.c = conf
	traceProfileDumper.c = conf
	cpuProfileDumper.c = conf
}
