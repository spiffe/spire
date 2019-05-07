package telemetry

// Constants for metric keys and labels. Helps with enforcement of non-conflicting usage of same or similar names.
// Additionally, importers of this package can get an idea of metric tags to look for.

const (
	// Activate functionality related to activating some element (such as X509 CA manager);
	// should be used with other tags to add clarity
	Activate = "activate"

	// AgentSVID tag a node (agent) SVID
	AgentSVID = "agent_svid"

	// Attest functionality related to attesting; should be used with other tags
	// to add clarity
	Attest = "attest"

	// Attestor tags an attestor type (eg. gcp, aws...)
	Attestor = "attestor"

	// AttestorName tags an attestor name
	AttestorName = "attestor_name"

	// Audience tags some audience for a token
	Audience = "audience"

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

	// CallerID tags an API caller; should be used with other tags
	// to add clarity
	CallerID = "caller_id"

	// Connection functionality related to some connection; should be used with other tags
	// to add clarity
	Connection = "connection"

	// Connections functionality related to some group of connections; should be used with other tags
	// to add clarity
	Connections = "connections"

	// Create functionality related to creating some entity; should be used with other tags
	// to add clarity
	Create = "create"

	// Delete functionality related to deleting some entity; should be used with other tags
	// to add clarity
	Delete = "delete"

	// DiscoveredSelectors tags selectors for some registration
	DiscoveredSelectors = "discovered_selectors"

	// ElapsedTime tags some duration of time; should be used with other tags to add clarity
	ElapsedTime = "elapsed_time"

	// Entry tag for some stored entry; should be used with other tags such as RegistrationAPI
	// to add clarity
	Entry = "entry"

	// Error tag for some error that occurred
	Error = "error"

	// ExpiringSVIDs tags expiring SVID count/list
	ExpiringSVIDs = "expiring_svids"

	// ExpiryCheckDuration tags duration for an expiry check; should be used with other tags
	// to add clarity
	ExpiryCheckDuration = "expiry_check_duration"

	// FederatedBundle functionality related to a federated bundle; should be used
	// with other tags to add clarity
	FederatedBundle = "federated_bundle"

	// Fetch functionality related to fetching some entity; should be used with other tags
	// to add clarity
	Fetch = "fetch"

	// FetchJWTSVID functionality related to fetching a JWT SVID
	FetchJWTSVID = "fetch_jwt_svid"

	// FetchJWTBundles functionality related to fetching JWT bundles
	FetchJWTBundles = "fetch_jwt_bundles"

	// FetchUpdates functionality related to fetching updates; should be used
	// with other tags to add clarity
	FetchUpdates = "fetch_updates"

	// FetchX509SVID functionality related to fetching an X509 SVID
	FetchX509SVID = "fetch_x509_svid"

	// JoinToken functionality related to a join token; should be used
	// with other tags to add clarity
	JoinToken = "join_token"

	// JWT declares JWT SVID type, clarifying metrics
	JWT = "jwt"

	// JWTKey functionality related to a JWT key; should be used with other tags
	// to add clarity
	JWTKey = "jwt_key"

	// JWTSVID functionality related to a JWT SVID; should be used with other tags
	// to add clarity
	JWTSVID = "jwt_svid"

	// List functionality related to listing some objects; should be used
	// with other tags to add clarity
	List = "list"

	// Manager functionality related to a manager (such as CA manager); should be
	// used with other tags to add clarity
	Manager = "manager"

	// NewSVID functionality related to creation of a new SVID
	NewSVID = "new_svid"

	// Node functionality related to a node entity or type; should be used with other tags
	// to add clarity
	Node = "node"

	// NodeAPI functionality related to attested/attesting nodes (agents)
	NodeAPI = "node_api"

	// Prepare functionality related to preparation of some entity; should be used with other tags
	// to add clarity
	Prepare = "prepare"

	// Prune functionality related to pruning some entity(ies); should be used with other tags
	// to add clarity
	Prune = "prune"

	// Pruned flagging something has been pruned
	Pruned = "pruned"

	// Registered flags whether some entity is registered or not; should be
	// either true or false
	Registered = "registered"

	// RegistrationAPI functionality related to the registration api; should be used
	// with other tags to add clarity
	RegistrationAPI = "registration_api"

	// Rotate functionality related to rotation of SVID; should be used with other tags
	// to add clarity
	Rotate = "rotate"

	// SDSAPI functionality related to SDS; should be used with other tags
	// to add clarity
	SDSAPI = "sds_api"

	// SDSPID tags an SDS PID
	SDSPID = "sds_pid"

	// Selector tags some registration selector
	Selector = "selector"

	// SendJWTBundleLatency tags latency for sending JWT bundle
	SendJWTBundleLatency = "send_jwt_bundle_latency"

	// ServerCA functionality related to a server CA; should be used with other tags
	// to add clarity
	ServerCA = "server_ca"

	// Sign functionality related to signing a token / cert; should be used with other tags
	// to add clarity
	Sign = "sign"

	// SPIFFEID tags a SPIFFE ID
	SPIFFEID = "spiffe_id"

	// Subject tags some subject (likely a SPIFFE ID, and likely for a token); should be used
	// with other tags to add clarity
	Subject = "subject"

	// SVID functionality related to a SVID; should be used with other tags
	// to add clarity
	SVID = "svid"

	// SVIDResponseLatency tags latency for SVID response
	SVIDResponseLatency = "svid_response_latency"

	// SVIDType tags some type of SVID (eg. X509, JWT)
	SVIDType = "svid_type"

	// Sync functionality for syncing (such as CA manager updates). Should
	// be used with other tags to add clarity
	Sync = "sync"

	// TTL functionality related to a time-to-live field; should be used
	// with other tags to add clarity
	TTL = "ttl"

	// TrustDomainID tags some trust domain ID
	TrustDomainID = "trust_domain_id"

	// Update functionality related to updating some entity; should be used
	// with other tags to add clarity
	Update = "update"

	// Updated tags some entity as updated; should be used
	// with other tags to add clarity
	Updated = "updated"

	// ValidateJWTSVID functionality related validating a JWT SVID
	ValidateJWTSVID = "validate_jwt_svid"

	// WorkloadAPI flagging usage of workload API; should be used with other tags
	// to add clarity
	WorkloadAPI = "workload_api"

	// WorkloadAttestationDuration tags duration of workload attestation
	WorkloadAttestationDuration = "workload_attestation_duration"

	// WorkloadAttestorLatency tags latency of a workload attestor
	WorkloadAttestorLatency = "workload_attestor_latency"

	// X509 declared X509 SVID type, clarifying metrics
	X509 = "x509"

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
