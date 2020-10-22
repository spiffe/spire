package api

type Names struct {
	// RawService is the unmodified service name
	RawService string

	// Service is the shortened service name (e.g. "svid.v1.SVID", "WorkloadAPI")
	Service string

	// ServiceMetric is the service name converted to a convenient form for
	// metric emission (i.e. snake_case)
	ServiceMetric string

	// Method is the method name (e.g. MintX509SVID)
	Method string

	// MethodMetric is the method name converted to a convenient form for
	// metric emission (i.e. snake_case)
	MethodMetric string
}
