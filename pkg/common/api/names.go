package api

type Names struct {
	// RawService is the unmodified service name
	RawService string

	// Service is the shortened service name (e.g. "svid.v1.SVID", "WorkloadAPI")
	Service string

	// Method is the method name (e.g. MintX509SVID)
	Method string

	// MetricKey is the metric key for the method
	MetricKey []string
}
