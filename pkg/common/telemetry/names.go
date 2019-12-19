package telemetry

// Constants for metric/log keys and labels. Helps with enforcement of non-conflicting usage of same or similar names.
// Additionally, importers of this package can get an idea of metric tags to look for.
// While these constants are exported, it is preferable to use the functions defined in subpackages, or
// define new such functions there

// Action metric tags or labels that are typically a specific action
const (
	// Action functionality related to actions themselves, such as rate-limiting an action
	Action = "action"

	// Activate functionality related to activating some element (such as X509 CA manager);
	// should be used with other tags to add clarity
	Activate = "activate"

	// Append functionality related to appending some element (such as part of a bundle);
	// should be used with other tags to add clarity
	Append = "append"

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

	// Set functionality related to set/override/clobber of an entity, such as a bundle;
	// should be used with other tags to add clarity
	Set = "set"

	// Sign functionality related to signing a token / cert; should be used with other tags
	// to add clarity
	Sign = "sign"

	// Sync functionality for syncing (such as CA manager updates). Should
	// be used with other tags to add clarity
	Sync = "sync"

	// Update functionality related to updating some entity; should be used
	// with other tags to add clarity
	Update = "update"

	// Mint functionality related to minting identities
	Mint = "mint"
)

// Attribute metric tags or labels that are typically an attribute of a
// larger entity or logic path
const (
	// Address tags some network address
	Address = "address"

	// Agent SPIFFE ID
	AgentID = "agent_id"

	// Attempt tags some count of attempts
	Attempt = "attempt"

	// Audience tags some audience for a token
	Audience = "audience"

	// CallerID tags an API caller; should be used with other tags
	// to add clarity
	CallerID = "caller_id"

	// CGroupPath tags a linux CGroup path, most likely for use in attestation
	CGroupPath = "cgroup_path"

	// Connection functionality related to some connection; should be used with other tags
	// to add clarity
	Connection = "connection"

	// Connections functionality related to some group of connections; should be used with other tags
	// to add clarity
	Connections = "connections"

	// ContainerID tags some container ID, most likely for use in attestation
	ContainerID = "container_id"

	// Count tags some basic count; should be used with other tags and clear messaging to add clarity
	Count = "count"

	// CsrSpiffeID represents the SPIFFE ID in a Certificate Signing Request.
	CsrSpiffeID = "csr_spiffe_id"

	// DatabaseType labels a database type (MySQL, postgres...)
	DatabaseType = "db_type"

	// DiscoveredSelectors tags selectors for some registration
	DiscoveredSelectors = "discovered_selectors"

	// DNS name is a name which is resolvable with DNS
	DNSName = "dns_name"

	// ElapsedTime tags some duration of time. Reserved for use in telemetry package on
	// call counters. Exported for tests only.
	ElapsedTime = "elapsed_time"

	// Error tag for some error that occurred. Limited usage, such as logging errors at
	// non-error level.
	Error = "error"

	// Expect tags an expected value, as opposed to the one received. Message should clarify
	// what kind of value was expected, and a different field should show the received value
	Expect = "expect"

	// Expiration tags an expiration time for some entity
	Expiration = "expiration"

	// ExpiryCheckDuration tags duration for an expiry check; should be used with other tags
	// to add clarity
	ExpiryCheckDuration = "expiry_check_duration"

	// FederatedAdded labels some count of federated bundles that have been added to an entity
	FederatedAdded = "fed_add"

	// FederatedRemoved labels some count of federated bundles that have been removed from an entity
	FederatedRemoved = "fed_rem"

	// Generation represents an objection generation (i.e. version)
	Generation = "generation"

	// IDType tags some type of ID (eg. registration ID, SPIFFE ID...)
	IDType = "id_type"

	// IssuedAt tags an issuance timestamp
	IssuedAt = "issued_at"

	// JWT declares JWT-SVID type, clarifying metrics
	JWT = "jwt"

	// JWTKeys tags some count or list of JWT Keys. Should NEVER provide the actual keys, use
	// Key IDs instead.
	JWTKeys = "jwt_keys"

	// Kid tags some key ID
	Kid = "kid"

	// NodeAttestorType declares the type of node attestation.
	NodeAttestorType = "node_attestor_type"

	// Nonce tags some nonce for communication
	Nonce = "nonce"

	// ParentID tags parent ID for an entry
	ParentID = "parent_id"

	// Path declares some logic path, likely on the file system
	Path = "path"

	// Peer ID is the SPIFFE ID of a peer
	PeerID = "peer_id"

	// PID declares some process ID
	PID = "pid"

	// PluginBuiltIn flags whether or not a plugin is built-in, or tags part of
	// the loading of built-in plugins
	PluginBuiltIn = "built-in_plugin"

	// PluginExternal flags whether or not a plugin is external, or tags part of
	// the loading of external plugins
	PluginExternal = "external_plugin"

	// PluginName tags name of some plugin
	PluginName = "plugin_name"

	// PluginService tags single service provided by a plugin
	PluginService = "plugin_service"

	// PluginServices tags services provided by a plugin
	PluginServices = "plugin_services"

	// PluginType tags type of some plugin
	PluginType = "plugin_type"

	// Pruned flagging something has been pruned
	Pruned = "pruned"

	// RegistrationID tags some registration entry ID
	RegistrationID = "entry_id"

	// Registered flags whether some entity is registered or not; should be
	// either true or false
	Registered = "registered"

	// RegistrationEntry tags a registration entry
	RegistrationEntry = "registration_entry"

	// ResourceNames tags some group of resources by name
	ResourceNames = "resource_names"

	// RetryInterval tags some interval for retry logic
	RetryInterval = "retry_interval"

	// Schema tags database schema version
	Schema = "schema"

	// Seconds tags some count of seconds; should be used with other tags and message
	// to add clarity
	Seconds = "seconds"

	// Selector tags some registration selector
	Selector = "selector"

	// Selectors tags some group of registration selector
	Selectors = "selectors"

	// SelectorsAdded labels some count of selectors that have been added to an entity
	SelectorsAdded = "selectors_added"

	// SelectorsRemoved labels some count of selectors that have been removed from an entity
	SelectorsRemoved = "selectors_removed"

	// SelfSigned tags whether or not some entity is self-signed
	SelfSigned = "self_signed"

	// SendJWTBundleLatency tags latency for sending JWT bundle
	SendJWTBundleLatency = "send_jwt_bundle_latency"

	// SerialNumber tags a certificate serial number
	SerialNumber = "serial_num"

	// SDSPID tags an SDS PID
	SDSPID = "sds_pid"

	// Slot X509 CA Slot ID
	Slot = "slot"

	// SPIFFEID tags a SPIFFE ID
	SPIFFEID = "spiffe_id"

	// Status tags status of call (OK, or some error), or status of some process
	Status = "status"

	// Subject tags some subject (likely a SPIFFE ID, and likely for a token); should be used
	// with other tags to add clarity
	Subject = "subject"

	// SVIDResponseLatency tags latency for SVID response
	SVIDResponseLatency = "svid_response_latency"

	// SVIDType tags some type of SVID (eg. X509, JWT)
	SVIDType = "svid_type"

	// SVIDUpdated tags that for some entity the SVID was updated
	SVIDUpdated = "svid_updated"

	// TTL functionality related to a time-to-live field; should be used
	// with other tags to add clarity
	TTL = "ttl"

	// TrustDomainID tags some trust domain ID
	TrustDomainID = "trust_domain_id"

	// Unknown tags some unknown caller, entity, or status
	Unknown = "unknown"

	// Updated tags some entity as updated; should be used
	// with other tags to add clarity
	Updated = "updated"

	// UpstreamBundle tags an upstream bundle for an entity
	UpstreamBundle = "upstream_bundle"

	// VersionInfo tags some version information
	VersionInfo = "version_info"

	// WorkloadAttestation tags call of overall workload attestation
	WorkloadAttestation = "workload_attestation"

	// WorkloadAttestor tags call of a workload attestor
	WorkloadAttestor = "workload_attestor"

	// X509 declared X509 SVID type, clarifying metrics
	X509 = "x509"

	// X509CAs tags some count or list of X509 CAs
	X509CAs = "x509_cas"
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

	// CAManager functionality related to a CA manager
	CAManager = "ca_manager"

	// CacheManager functionality related to a cache manager
	CacheManager = "cache_manager"

	// Catalog functionality related to plugin catalog
	Catalog = "catalog"

	// Datastore functionality related to datastore plugin
	Datastore = "datastore"

	// Endpoints functionality related to agent/server endpoints
	Endpoints = "endpoints"

	// Entry tag for some stored entry; should be used with other tags such as RegistrationAPI
	// to add clarity
	Entry = "entry"

	// Event tag some event that has occurred, for a notifier, watcher, listener, etc.
	Event = "event"

	// ExpiringSVIDs tags expiring SVID count/list
	ExpiringSVIDs = "expiring_svids"

	// FederatedBundle functionality related to a federated bundle; should be used
	// with other tags to add clarity
	FederatedBundle = "federated_bundle"

	// JoinToken functionality related to a join token; should be used
	// with other tags to add clarity
	JoinToken = "join_token"

	// JWTKey functionality related to a JWT key; should be used with other tags
	// to add clarity. Should NEVER actually provide the key itself, use Key ID instead.
	JWTKey = "jwt_key"

	// JWTSVID functionality related to a JWT-SVID; should be used with other tags
	// to add clarity
	JWTSVID = "jwt_svid"

	// Manager functionality related to a manager (such as CA manager); should be
	// used with other tags to add clarity
	Manager = "manager"

	// Method is the full name of the method invoked
	Method = "method"

	// NewSVID functionality related to creation of a new SVID
	NewSVID = "new_svid"

	// Node functionality related to a node entity or type; should be used with other tags
	// to add clarity
	Node = "node"

	// Notifier functionality related to some notifying entity; should be used with other tags
	// to add clarity
	Notifier = "notifier"

	// ServerCA functionality related to a server CA; should be used with other tags
	// to add clarity
	ServerCA = "server_ca"

	// SpireAgent typically the entire spire agent service
	SpireAgent = "spire_agent"

	// SpireServer typically the entire spire server
	SpireServer = "spire_server"

	// SVID functionality related to a SVID; should be used with other tags
	// to add clarity
	SVID = "svid"

	// SVIDRotator functionality related to a SVID rotator
	SVIDRotator = "svid_rotator"

	// RegistrationManager functionality related to a registration manager
	RegistrationManager = "registration_manager"

	// Telemetry tags a telemetry module
	Telemetry = "telemetry"

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

	// CreateFederatedBundle functionality related to creating a federated bundle
	CreateFederatedBundle = "create_federated_bundle"

	// CreateJoinToken functionality related to creating a join token
	CreateJoinToken = "create_join_token"

	// CreateRegistrationEntry functionality related to creating a registration entry
	CreateRegistrationEntry = "create_registration_entry"

	// DeleteFederatedBundle functionality related to deleting a federated bundle
	DeleteFederatedBundle = "delete_federated_bundle"

	// DeleteRegistrationEntry functionality related to deleting a registration entry
	DeleteRegistrationEntry = "delete_registration_entry"

	// EvictAgent funtionality related to evicting an agent
	EvictAgent = "evict_agent"

	// FetchBundle functionality related to fetching a CA bundle
	FetchBundle = "fetch_bundle"

	// FetchFederatedBundle functionality related to fetching a federated bundle
	FetchFederatedBundle = "fetch_federated_bundle"

	// FetchJWTSVID functionality related to fetching a JWT-SVID
	FetchJWTSVID = "fetch_jwt_svid"

	// FetchJWTBundles functionality related to fetching JWT bundles
	FetchJWTBundles = "fetch_jwt_bundles"

	// FetchRegistrationEntry functionality related to fetching a registration entry
	FetchRegistrationEntry = "fetch_registration_entry"

	// FetchRegistrationEntries functionality related to fetching registration entries
	FetchRegistrationEntries = "fetch_registration_entries"

	// FetchSecrets functionality related to fetching secrets
	FetchSecrets = "fetch_secrets"

	// FetchUpdates functionality related to fetching updates; should be used
	// with other tags to add clarity
	FetchUpdates = "fetch_updates"

	// FetchX509CASVID functionality related to fetching an X509 SVID
	FetchX509CASVID = "fetch_x509_ca_svid"

	// FetchX509SVID functionality related to fetching an X509 SVID
	FetchX509SVID = "fetch_x509_svid"

	// GetNodeSelectors functionality related to getting node selectors
	GetNodeSelectors = "get_node_selectors"

	// ListAgents functionality related to listing agents
	ListAgents = "list_agents"

	// ListFederatedBundles functionality related to listing federated bundles
	ListFederatedBundles = "list_federated_bundles"

	// ListRegistrationsByParentID functionality related to listing registrations by parent ID
	ListRegistrationsByParentID = "list_registrations_by_parent_id"

	// ListRegistrationsBySelector functionality related to listing registrations by selector
	ListRegistrationsBySelector = "list_registrations_by_selector"

	// ListRegistrationsBySelectors functionality related to listing registrations by selectors
	ListRegistrationsBySelectors = "list_registrations_by_selectors"

	// ListRegistrationsBySPIFFEID functionality related to listing registrations by SPIFFE ID
	ListRegistrationsBySPIFFEID = "list_registrations_by_spiffe_id"

	// MintJWTSVID functionality related to minting a JWT-SVID
	MintJWTSVID = "mint_jwt_svid"

	// MintX509SVID functionality related to minting an X.509 SVID
	MintX509SVID = "mint_x509_svid"

	// NodeAPI functionality related to attested/attesting nodes (agents)
	NodeAPI = "node_api"

	// RegistrationAPI functionality related to the registration api; should be used
	// with other tags to add clarity
	RegistrationAPI = "registration_api"

	// SDSAPI functionality related to SDS; should be used with other tags
	// to add clarity
	SDSAPI = "sds_api"

	// StreamSecrets functionality related to streaming secrets
	StreamSecrets = "stream_secrets"

	// SubsystemName declares field for some subsystem name (an API, module...)
	SubsystemName = "subsystem_name"

	// UpdateFederatedBundle functionality related to updating a federated bundle
	UpdateFederatedBundle = "update_federated_bundle"

	// UpdateRegistrationEntry functionality related to updating a registration entry
	UpdateRegistrationEntry = "update_registration_entry"

	// ValidateJWTSVID functionality related validating a JWT-SVID
	ValidateJWTSVID = "validate_jwt_svid"

	// WorkloadAPI flagging usage of workload API; should be used with other tags
	// to add clarity
	WorkloadAPI = "workload_api"
)
