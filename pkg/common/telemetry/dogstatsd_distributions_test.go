package telemetry

import (
	"net"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-metrics/datadog"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// receiveDogStatsdLines collects the lines sent to conn until want lines
// have arrived or the deadline passes.
func receiveDogStatsdLines(t *testing.T, conn net.PacketConn, want int) []string {
	var lines []string
	buf := make([]byte, 65536)
	deadline := time.Now().Add(10 * time.Second)
	for len(lines) < want && time.Now().Before(deadline) {
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(500*time.Millisecond)))
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			continue
		}
		for line := range strings.SplitSeq(string(buf[:n]), "\n") {
			if line != "" {
				lines = append(lines, line)
			}
		}
	}
	sort.Strings(lines)
	return lines
}

func listenUDP(t *testing.T) net.PacketConn {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	return conn
}

type dogStatsdTestSink interface {
	Sink
	Shutdown()
}

func emitDogStatsdTestMetrics(sink dogStatsdTestSink) {
	labels := []Label{{Name: "status", Value: "OK"}, {Name: "a:b c", Value: "x:y z"}, {Name: "empty", Value: ""}}
	sink.SetGaugeWithLabels([]string{"spire_agent", "started"}, 1, labels)
	sink.SetGauge([]string{"spire_agent", "uptime_in_ms"}, 2)
	sink.IncrCounterWithLabels([]string{"spire_agent", "rpc", "fetch"}, 3, labels)
	sink.IncrCounter([]string{"spire_agent", "with space", "colon:key"}, 4)
	sink.AddSampleWithLabels([]string{"spire_agent", "workload_api", "discovered_selectors"}, 5, labels)
	sink.AddSample([]string{"spire_agent", "", "empty_part"}, 6)
	sink.AddSampleWithLabels([]string{"spire_agent", "rpc", "fetch", ElapsedTime}, 8, labels)
	sink.EmitKey([]string{"spire_agent", "ignored"}, 7)
	sink.Shutdown()
}

func TestDogStatsdLatencySinkMatchesGoMetrics(t *testing.T) {
	goMetricsConn := listenUDP(t)
	goMetricsSink, err := datadog.NewDogStatsdSink(goMetricsConn.LocalAddr().String(), "")
	require.NoError(t, err)
	emitDogStatsdTestMetrics(goMetricsSink)
	expected := receiveDogStatsdLines(t, goMetricsConn, 7)
	require.Len(t, expected, 7)

	conn := listenUDP(t)
	sink, err := newDogStatsdLatencySink(conn.LocalAddr().String())
	require.NoError(t, err)
	emitDogStatsdTestMetrics(sink)

	var distributions, others []string
	for _, line := range receiveDogStatsdLines(t, conn, 8) {
		if strings.Contains(line, "|d") {
			distributions = append(distributions, line)
			continue
		}
		others = append(others, line)
	}
	assert.Equal(t, expected, others, "every metric the go-metrics sink submits is submitted unchanged")
	assert.Equal(t, []string{"spire_agent.rpc.fetch.elapsed_time.histogram:8|d|#status:OK,a_b_c:x_y_z,empty"}, distributions)
}

func TestDogStatsdLatencySinkSubmitsDistributions(t *testing.T) {
	conn := listenUDP(t)
	sink, err := newDogStatsdLatencySink(conn.LocalAddr().String())
	require.NoError(t, err)

	sink.AddSampleWithLabels([]string{"spire_agent", "rpc", "fetch", ElapsedTime}, 12.5, []Label{{Name: "status", Value: "OK"}})
	sink.AddSample([]string{"spire_agent", "manager", "sync", ElapsedTime}, 3)
	sink.Shutdown()

	assert.Equal(t, []string{
		"spire_agent.manager.sync.elapsed_time.histogram:3|d",
		"spire_agent.manager.sync.elapsed_time:3.000000|ms",
		"spire_agent.rpc.fetch.elapsed_time.histogram:12.5|d|#status:OK",
		"spire_agent.rpc.fetch.elapsed_time:12.500000|ms|#status:OK",
	}, receiveDogStatsdLines(t, conn, 4))
}

func TestDogStatsdRunnerLatencyHistograms(t *testing.T) {
	config := testDogStatsdConfig()
	runner, err := newDogStatsdRunner(config)
	require.NoError(t, err)
	assert.IsType(t, &datadog.DogStatsdSink{}, runner.sinks()[0])

	enabled := true
	config.FileConfig.EnableLatencyHistograms = &enabled
	runner, err = newDogStatsdRunner(config)
	require.NoError(t, err)
	assert.IsType(t, &dogStatsdLatencySink{}, runner.sinks()[0])
}

func TestDogStatsdLatencyHistogramsThroughMetrics(t *testing.T) {
	conn := listenUDP(t)
	log, _ := test.NewNullLogger()
	disabled, enabled := false, true
	metrics, err := NewMetrics(&MetricsConfig{
		Logger:      log,
		ServiceName: "spire_agent",
		FileConfig: FileConfig{
			DogStatsd:               []DogStatsdConfig{{Address: conn.LocalAddr().String()}},
			EnableHostnameLabel:     &disabled,
			EnableLatencyHistograms: &enabled,
		},
	})
	require.NoError(t, err)

	call := StartCall(metrics, "rpc", "fetch")
	callErr := status.Error(codes.Unavailable, "unavailable")
	call.Done(&callErr)
	StartCall(metrics, "rpc", "fetch").Done(nil)
	metrics.AddSample([]string{"workload_api", "discovered_selectors"}, 2)

	lines := receiveDogStatsdLines(t, conn, 7)
	types := make(map[string]string)
	for _, line := range lines {
		name, rest, ok := strings.Cut(line, ":")
		require.True(t, ok, line)
		parts := strings.Split(rest, "|")
		require.GreaterOrEqual(t, len(parts), 2, line)
		types[name] = parts[1]
	}
	assert.Equal(t, map[string]string{
		"spire_agent.rpc.fetch":                         "c",
		"spire_agent.rpc.fetch.elapsed_time":            "ms",
		"spire_agent.rpc.fetch.elapsed_time.histogram":  "d",
		"spire_agent.workload_api.discovered_selectors": "ms",
	}, types)
}
