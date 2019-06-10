package telemetry

// Constants for metric keys and labels. Helps with enforcement of non-conflicting usage of same or similar names.
// Additionally, importers of this package can get an idea of metric tags to look for.
// While these constants are exported, it is preferable to use the functions defined in subpackages, or
// define new such functions there

// Action metric tags or labels that are typically a specific action
const (
	// Activate functionality related to activating some element (such as X509 CA manager);
	// should be used with other tags to add clarity
	Activate = "activate"

	// Attest functionality related to attesting; should be used with other tags
	// to add clarity
	Attest = "attest"

	// Create functionality related to creating some entity; should be used with other tags
	// to add clarity
	Create = "create"

	// Delete functionality related to deleting some entity; should be used with other tags
	// to add clarity
	Delete = "delete"

	// Fetch functionality related to fetching some entity; should be used with other tags
	// to add clarity
	Fetch = "fetch"

	// List functionality related to listing some objects; should be used
	// with other tags to add clarity
	List = "list"

	// Prepare functionality related to preparation of some entity; should be used with other tags
	// to add clarity
	Prepare = "prepare"

	// Prune functionality related to pruning some entity(ies); should be used with other tags
	// to add clarity
	Prune = "prune"

	// Rotate functionality related to rotation of SVID; should be used with other tags
	// to add clarity
	Rotate = "rotate"

	// Sign functionality related to signing a token / cert; should be used with other tags
	// to add clarity
	Sign = "sign"

	// Sync functionality for syncing (such as CA manager updates). Should
	// be used with other tags to add clarity
	Sync = "sync"

	// Update functionality related to updating some entity; should be used
	// with other tags to add clarity
	Update = "update"
)

// Attribute metric tags or labels that are typically an attribute of a
// larger entity or logic path
const (
	// Audience tags some audience for a token
	Audience = "audience"

	// CallerID tags an API caller; should be used with other tags
	// to add clarity
	CallerID = "caller_id"

	// Connection functionality related to some connection; should be used with other tags
	// to add clarity
	Connection = "connection"

	// Connections functionality related to some group of connections; should be used with other tags
	// to add clarity
	Connections = "connections"

	// DiscoveredSelectors tags selectors for some registration
	DiscoveredSelectors = "discovered_selectors"

	// ElapsedTime tags some duration of time. Reserved for use in telemetry package on
	// call counters. Exported for tests only.
	ElapsedTime = "elapsed_time"

	// Error tag for some error that occurred
	Error = "error"

	// ExpiryCheckDuration tags duration for an expiry check; should be used with other tags
	// to add clarity
	ExpiryCheckDuration = "expiry_check_duration"

	// JWT declares JWT SVID type, clarifying metrics
	JWT = "jwt"

	// Pruned flagging something has been pruned
	Pruned = "pruned"

	// Registered flags whether some entity is registered or not; should be
	// either true or false
	Registered = "registered"

	// RegistrationEntry tags a registration entry
	RegistrationEntry = "registration_entry"

	// Selector tags some registration selector
	Selector = "selector"

	// SendJWTBundleLatency tags latency for sending JWT bundle
	SendJWTBundleLatency = "send_jwt_bundle_latency"

	// SDSPID tags an SDS PID
	SDSPID = "sds_pid"

	// SPIFFEID tags a SPIFFE ID
	SPIFFEID = "spiffe_id"

	// Subject tags some subject (likely a SPIFFE ID, and likely for a token); should be used
	// with other tags to add clarity
	Subject = "subject"

	// SVIDResponseLatency tags latency for SVID response
	SVIDResponseLatency = "svid_response_latency"

	// SVIDType tags some type of SVID (eg. X509, JWT)
	SVIDType = "svid_type"

	// TTL functionality related to a time-to-live field; should be used
	// with other tags to add clarity
	TTL = "ttl"

	// TrustDomainID tags some trust domain ID
	TrustDomainID = "trust_domain_id"

	// Updated tags some entity as updated; should be used
	// with other tags to add clarity
	Updated = "updated"

	// WorkloadAttestationDuration tags duration of workload attestation
	WorkloadAttestationDuration = "workload_attestation_duration"

	// WorkloadAttestorLatency tags latency of a workload attestor
	WorkloadAttestorLatency = "workload_attestor_latency"

	// X509 declared X509 SVID type, clarifying metrics
	X509 = "x509"
)

// Entity metric tags or labels that are typically an entity or
// module in their own right, rather than descriptive of other
// entities or modules
const (
	// AgentSVID tag a node (agent) SVID
	AgentSVID = "agent_svid"

	// Attestor tags an attestor plugin/type (eg. gcp, aws...)
	Attestor = "attestor"

	// Bundle functionality related to a bundle; should be used with other tags
	// to add clarity
	Bundle = "bundle"

	// BundlesUpdate functionality related to updating bundles
	BundlesUpdate = "bundles_update"

	// CA functionality related to some CA; should be used with other tags
	// to add clarity
	CA = "ca"

	// CacheManager functionality related to a cache manager
	CacheManager = "cache_manager"

	// Entry tag for some stored entry; should be used with other tags such as RegistrationAPI
	// to add clarity
	Entry = "entry"

	// ExpiringSVIDs tags expiring SVID count/list
	ExpiringSVIDs = "expiring_svids"

	// FederatedBundle functionality related to a federated bundle; should be used
	// with other tags to add clarity
	FederatedBundle = "federated_bundle"

	// JoinToken functionality related to a join token; should be used
	// with other tags to add clarity
	JoinToken = "join_token"

	// JWTKey functionality related to a JWT key; should be used with other tags
	// to add clarity
	JWTKey = "jwt_key"

	// JWTSVID functionality related to a JWT SVID; should be used with other tags
	// to add clarity
	JWTSVID = "jwt_svid"

	// Manager functionality related to a manager (such as CA manager); should be
	// used with other tags to add clarity
	Manager = "manager"

	// NewSVID functionality related to creation of a new SVID
	NewSVID = "new_svid"

	// Node functionality related to a node entity or type; should be used with other tags
	// to add clarity
	Node = "node"

	// ServerCA functionality related to a server CA; should be used with other tags
	// to add clarity
	ServerCA = "server_ca"

	// SVID functionality related to a SVID; should be used with other tags
	// to add clarity
	SVID = "svid"

	// X509CA functionality related to an x509 CA; should be used with other tags
	// to add clarity
	X509CA = "x509_ca"

	// X509CASVID functionality related to an x509 CA SVID; should be used with other tags
	// to add clarity
	X509CASVID = "x509_ca_svid"

	// X509SVID functionality related to an x509 SVID; should be used with other tags
	// to add clarity
	X509SVID = "x509_svid"
)

// Operation metric tags or labels that are typically a specific
// operation or API
const (
	// FetchJWTSVID functionality related to fetching a JWT SVID
	FetchJWTSVID = "fetch_jwt_svid"

	// FetchJWTBundles functionality related to fetching JWT bundles
	FetchJWTBundles = "fetch_jwt_bundles"

	// FetchUpdates functionality related to fetching updates; should be used
	// with other tags to add clarity
	FetchUpdates = "fetch_updates"

	// FetchX509SVID functionality related to fetching an X509 SVID
	FetchX509SVID = "fetch_x509_svid"

	// NodeAPI functionality related to attested/attesting nodes (agents)
	NodeAPI = "node_api"

	// RegistrationAPI functionality related to the registration api; should be used
	// with other tags to add clarity
	RegistrationAPI = "registration_api"

	// SDSAPI functionality related to SDS; should be used with other tags
	// to add clarity
	SDSAPI = "sds_api"

	// ValidateJWTSVID functionality related validating a JWT SVID
	ValidateJWTSVID = "validate_jwt_svid"

	// WorkloadAPI flagging usage of workload API; should be used with other tags
	// to add clarity
	WorkloadAPI = "workload_api"
)
