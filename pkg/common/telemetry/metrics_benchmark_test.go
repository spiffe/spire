package telemetry

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var (
	key    = []string{"key1", "key2", "key3"}
	valf   = float32(5.0)
	labels = []Label{
		{
			Name:  "lkey1",
			Value: "lval1",
		},
		{
			Name:  "lkey2",
			Value: "lval2",
		},
	}
	valt = time.Now()
)

func BenchmarkDogStatsd(b *testing.B) {
	m := getDogStatsdMetricImpl(b)

	benchmarkMetricImpl(b, m)
}

func BenchmarkInMem(b *testing.B) {
	m := getInMemMetricImpl(b)

	benchmarkMetricImpl(b, m)
}

func BenchmarkM3(b *testing.B) {
	m := getM3MetricImpl(b)

	benchmarkMetricImpl(b, m)
}

func BenchmarkPrometheus(b *testing.B) {
	m := getPrometheusMetricImpl(b)

	benchmarkMetricImpl(b, m)
}

func BenchmarkStatsd(b *testing.B) {
	listener, err := net.ListenPacket(statsdProtocol, "localhost:")
	if err != nil {
		require.NoError(b, err)
	}
	defer listener.Close()

	port := listener.LocalAddr().(*net.UDPAddr).Port

	m := getStatsdMetricImpl(b, port)

	benchmarkMetricImpl(b, m)
}

func benchmarkMetricImpl(b *testing.B, m Metrics) {
	b.Run("SetGauge", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			m.SetGauge(key, valf)
		}
	})

	b.Run("SetGaugeWithLabels", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			m.SetGaugeWithLabels(key, valf, labels)
		}
	})

	b.Run("EmitKey", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			m.EmitKey(key, valf)
		}
	})

	b.Run("IncrCounter", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			m.IncrCounter(key, valf)
		}
	})

	b.Run("IncrCounterWithLabels", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			m.IncrCounterWithLabels(key, valf, labels)
		}
	})

	b.Run("AddSample", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			m.AddSample(key, valf)
		}
	})

	b.Run("AddSampleWithLabels", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			m.AddSampleWithLabels(key, valf, labels)
		}
	})

	b.Run("MeasureSince", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			m.MeasureSince(key, valt)
		}
	})

	b.Run("MeasureSinceWithLabels", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			m.MeasureSinceWithLabels(key, valt, labels)
		}
	})
}

func getDogStatsdMetricImpl(b *testing.B) Metrics {
	m, err := NewMetrics(testDogStatsdConfig())
	if err != nil {
		require.NoError(b, err)
	}
	return m
}

func getInMemMetricImpl(b *testing.B) Metrics {
	m, err := NewMetrics(testInmemConfig())
	if err != nil {
		require.NoError(b, err)
	}
	return m
}

func getM3MetricImpl(b *testing.B) Metrics {
	m, err := NewMetrics(testM3Config())
	if err != nil {
		require.NoError(b, err)
	}
	return m
}

func getPrometheusMetricImpl(b *testing.B) Metrics {
	m, err := NewMetrics(testPrometheusConfig())
	if err != nil {
		require.NoError(b, err)
	}
	return m
}

func getStatsdMetricImpl(b *testing.B, port int) Metrics {
	m, err := NewMetrics(testStatsdConfig(port))
	if err != nil {
		require.NoError(b, err)
	}
	return m
}
