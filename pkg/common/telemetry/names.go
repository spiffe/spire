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

	// Create if not exists functionality related to creating some entity; should be used with
	// other tags to add clarity
	CreateIfNotExists = "create_if_not_exists"

	// Delete functionality related to deleting some entity; should be used with other tags
	// to add clarity
	Delete = "delete"

	// Fetch functionality related to fetching some entity; should be used with other tags
	// to add clarity
	Fetch = "fetch"

	// FetchPrivateKey related to fetching a private in the KeyManager plugin interface
	// (agent)
	FetchPrivateKey = "fetch_private_key"

	// GenerateKey related to generating a key  in the KeyManager plugin interface
	// (server)
	GenerateKey = "generate_key"

	// GenerateKeyPair related to generating a key pair in the KeyManager plugin interface
	// (agent)
	GenerateKeyPair = "generate_key_pair"

	// GetKey related to getting a key in the KeyManager plugin interface
	// (agent)
	GetKey = "get_key"

	// GetKeys related to getting keys in the KeyManager plugin interface
	// (agent)
	GetKeys = "get_keys"

	// GetPublicKey related to getting a key in the KeyManager plugin interface
	// (server)
	GetPublicKey = "get_public_key"

	// GetPublicKeys related to getting keys in the KeyManager plugin interface
	// (server)
	GetPublicKeys = "get_public_keys"

	// Keys related to keys used on HCL
	Keys = "keys"

	// List functionality related to listing some objects; should be used
	// with other tags to add clarity
	List = "list"

	// Prepare functionality related to preparation of some entity; should be used with other tags
	// to add clarity
	Prepare = "prepare"

	// Prune functionality related to pruning some entity(ies); should be used with other tags
	// to add clarity
	Prune = "prune"

	// Push functionality related to pushing some entity to let a destination know
	// that some source generated such entity; should be used with other tags
	// to add clarity
	Push = "push"

	// Reload functionality related to reloading of a cache
	Reload = "reload"

	// Rotate functionality related to rotation of SVID; should be used with other tags
	// to add clarity
	Rotate = "rotate"

	// Set functionality related to set/override/clobber of an entity, such as a bundle;
	// should be used with other tags to add clarity
	Set = "set"

	// Sign functionality related to signing a token / cert; should be used with other tags
	// to add clarity
	Sign = "sign"

	// SignData related to signing data in the KeyManager plugin interface
	// (server)
	SignData = "sign_data"

	// StorePrivateKey related to storing a private key in the KeyManager plugin interface
	// (agent or server)
	StorePrivateKey = "store_private_key"

	// StoreSVIDUpdates related to storing SVID updates in SVIDStore plugins
	StoreSVIDUpdates = "store_svid_updates"

	// Sync functionality for syncing (such as CA manager updates). Should
	// be used with other tags to add clarity
	Sync = "sync"

	// Update functionality related to updating some entity; should be used
	// with other tags to add clarity
	Update = "update"

	// Mint functionality related to minting identities
	Mint = "mint"

	// Taint functionality related with tainting a key from the bundle
	Taint = "taint"

	// Revoke functionality related with revoking a key from the bundle
	Revoke = "revoke"
)

// Attribute metric tags or labels that are typically an attribute of a
// larger entity or logic path
const (
	// Address tags some network address
	Address = "address"

	// Admin tags admin access
	Admin = "admin"

	// AdminIDs are admin IDs
	AdminIDs = "admin_ids"

	// Agent SPIFFE ID
	AgentID = "agent_id"

	// Attempt tags some count of attempts
	Attempt = "attempt"

	// Audience tags some audience for a token
	Audience = "audience"

	// AuthorizedAs indicates who an entity was authorized as
	AuthorizedAs = "authorized_as"

	// AuthorizedVia indicates by what means an entity was authorized
	AuthorizedVia = "authorized_via"

	// BundleEndpointProfile is the name of the bundle endpoint profile
	BundleEndpointProfile = "bundle_endpoint_profile"

	// BundleEndpointURL is the URL of the bundle endpoint
	BundleEndpointURL = "bundle_endpoint_url"

	// ByBanned tags filtering by banned agents
	ByBanned = "by_banned"

	// ByCanReattest tags filtering by agents that can re-attest
	ByCanReattest = "by_can_reattest"

	// BySelectorMatch tags Match used when filtering by Selectors
	BySelectorMatch = "by_selector_match"

	// BySelectors tags selectors used when filtering
	BySelectors = "by_selectors"

	// CallerAddr labels an API caller address
	CallerAddr = "caller_addr"

	// CallerID tags an API caller; should be used with other tags
	// to add clarity
	CallerID = "caller_id"

	// CallerUID tags an API caller user ID; should be used with other tags
	// to add clarity; Unix only
	CallerUID = "caller_uid"

	// CallerSID tags an API caller user SID; should be used with other tags
	// to add clarity; Windows only
	CallerUserSID = "caller_user_sid"

	// CallerGID tags an API caller group ID; should be used with other tags
	// to add clarity; Unix only
	CallerGID = "caller_gid"

	// CallerPath tags an API caller binary path; should be used with other tags
	// to add clarity
	CallerPath = "caller_path"

	// CertFilePath tags a certificate file path used for TLS connections.
	CertFilePath = "cert_file_path"

	// KeyFilePath tags a key file path used for TLS connections.
	KeyFilePath = "key_file_path"

	// CGroupPath tags a linux CGroup path, most likely for use in attestation
	CGroupPath = "cgroup_path"

	// Check tags a health check subsystem
	Check = "check"

	// Connection functionality related to some connection; should be used with other tags
	// to add clarity
	Connection = "connection"

	// Connections functionality related to some group of connections; should be used with other tags
	// to add clarity
	Connections = "connections"

	// ContainerID tags some container ID, most likely for use in attestation
	ContainerID = "container_id"

	// ContainerName tags some container name, most likely for use in attestation
	ContainerName = "container_name"

	// Count tags some basic count; should be used with other tags and clear messaging to add clarity
	Count = "count"

	// CreatedAt tags registration entry creation date
	CreatedAt = "created_at"

	// Csr represents a presented Csr in hashed format. It's hashed using the hex-encoded SHA256 checksum.
	Csr = "csr"

	// CsrSpiffeID represents the SPIFFE ID in a Certificate Signing Request.
	CsrSpiffeID = "csr_spiffe_id"

	// DataDir is a data directory
	DataDir = "data_dir"

	// DatabaseType labels a database type (MySQL, postgres...)
	DatabaseType = "db_type"

	// DeprecatedServiceName tags the deprecated service name
	DeprecatedServiceName = "deprecated_service_name"

	// Details tags details response from a health check subsystem
	Details = "details"

	// Duration is the amount of seconds that an error is active
	Duration = "duration"

	// DiscoveredSelectors tags selectors for some registration
	DiscoveredSelectors = "discovered_selectors"

	// DNS name is a name which is resolvable with DNS
	DNSName = "dns_name"

	// Downstream tags if entry is a downstream
	Downstream = "downstream"

	// ElapsedTime tags some duration of time.
	ElapsedTime = "elapsed_time"

	// EntryAdded is the counter key for when a entry is added to LRU cache
	EntryAdded = "lru_cache_entry_add"

	// EntryRemoved is the counter key for when a entry is removed from LRU cache
	EntryRemoved = "lru_cache_entry_remove"

	// EntryUpdated is the counter key for when an LRU cache entry is updated
	EntryUpdated = "lru_cache_entry_update"

	// EndpointSpiffeID tags endpoint SPIFFE ID
	EndpointSpiffeID = "endpoint_spiffe_id"

	// Error tag for some error that occurred. Limited usage, such as logging errors at
	// non-error level.
	Error = "error"

	// Expect tags an expected value, as opposed to the one received. Message should clarify
	// what kind of value was expected, and a different field should show the received value
	Expect = "expect"

	// ExpectGID is like Expect, specific to gid.
	ExpectGID = "expect_gid"

	// ExpectStartTime is like Expect, specific to a start time.
	ExpectStartTime = "expect_start_time"

	// ExpectUID is like Expect, specific to uid.
	ExpectUID = "expect_uid"

	// Expiration tags an expiration time for some entity
	Expiration = "expiration"

	// ExpiresAt tags registration entry expiration
	ExpiresAt = "expires_at"

	// ExpiryCheckDuration tags duration for an expiry check; should be used with other tags
	// to add clarity
	ExpiryCheckDuration = "expiry_check_duration"

	// External tag something as external (e.g. external plugin)
	External = "external"

	// Failures amount of concatenated errors
	Failures = "failures"

	// FederatedAdded labels some count of federated bundles that have been added to an entity
	FederatedAdded = "fed_add"

	// FederatedRemoved labels some count of federated bundles that have been removed from an entity
	FederatedRemoved = "fed_rem"

	// FederatesWith tags a federates with list
	FederatesWith = "federates_with"

	// FederatesWithMatch tags a federates with match filter
	FederatesWithMatch = "federates_with_match"

	// FederationRelationship tags a federation relationship
	FederationRelationship = "federation_relationship"

	// Generation represents an objection generation (i.e. version)
	Generation = "generation"

	// Hint tags registration entry hint
	Hint = "hint"

	// IDType tags some type of ID (eg. registration ID, SPIFFE ID...)
	IDType = "id_type"

	// IssuedAt tags an issuance timestamp
	IssuedAt = "issued_at"

	// JWT declares JWT-SVID type, clarifying metrics
	JWT = "jwt"

	// JWTAuthorityExpiresAt tags a JWT Authority expiration
	JWTAuthorityExpiresAt = "jwt_authority_expires_at"

	// JWTAuthorityPublicKey tags a JWT authority key ID
	JWTAuthorityKeyID = "jwt_authority_key_id"

	// JWTAuthorityPublicKeySHA256 tags a JWT Authority public key
	JWTAuthorityPublicKeySHA256 = "jwt_authority_public_key_sha256"

	// JWTKeys tags some count or list of JWT Keys. Should NEVER provide the actual keys, use
	// Key IDs instead.
	JWTKeys = "jwt_keys"

	// Kid tags some key ID
	Kid = "kid"

	// LocalAuthorityID tags a local authority ID
	LocalAuthorityID = "local_authority_id"

	// Mode tags a bundle deletion mode
	Mode = "mode"

	// Network tags some network name ("tcp", "udp")
	Network = "network"

	// NewSerialNumber tags a certificate new serial number
	NewSerialNumber = "new_serial_num"

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

	// PluginName tags name of some plugin
	PluginName = "plugin_name"

	// PluginService tags single service provided by a plugin
	PluginService = "plugin_service"

	// PluginServices tags services provided by a plugin
	PluginServices = "plugin_services"

	// PluginType tags type of some plugin
	PluginType = "plugin_type"

	// PodUID tags some pod UID, most likely for use in attestation
	PodUID = "pod_uid"

	// PreferredServiceName tags the preferred service name
	PreferredServiceName = "preferred_service_name"

	// Pruned flagging something has been pruned
	Pruned = "pruned"

	// ReadOnly tags something read-only
	ReadOnly = "read_only"

	// Reason is the reason for something
	Reason = "reason"

	// Reattestable declares if the agent should reattest when its SVID expires
	Reattestable = "rettestable"

	// Received tags a received value, as opposed to the one that is expected. Message should clarify
	// what kind of value was received, and a different field should show the expected value.
	Received = "received"

	// ReceivedGID is like Received, specific to gid.
	ReceivedGID = "received_gid"

	// ReceivedStartTime is like Received, specific to a start time.
	ReceivedStartTime = "received_start_time"

	// ReceivedUID is like Received, specific to uid.
	ReceivedUID = "received_uid"

	// RecordMapSize is the gauge key to hold the size of the LRU cache entries map
	RecordMapSize = "lru_cache_record_map_size"

	// RefreshHint tags a bundle refresh hint
	RefreshHint = "refresh_hint"

	// RegistrationID tags some registration entry ID
	RegistrationID = "entry_id"

	// Registered flags whether some entity is registered or not; should be
	// either true or false
	Registered = "registered"

	// RegistrationEntry tags a registration entry
	RegistrationEntry = "registration_entry"

	// RegistrationEntryEvent is a notice a registration entry has been create, modified, or deleted
	RegistrationEntryEvent = "registration_entry_event"

	// RequestID tags a request identifier
	RequestID = "request_id"

	// ResourceNames tags some group of resources by name
	ResourceNames = "resource_names"

	// RetryInterval tags some interval for retry logic
	RetryInterval = "retry_interval"

	// RevisionNumber tags a registration entry revision number
	RevisionNumber = "revision_number"

	// Schema tags database schema version
	Schema = "schema"

	// Seconds tags some count of seconds; should be used with other tags and message
	// to add clarity
	Seconds = "seconds"

	// SequenceNumber tags a bundle sequence number
	SequenceNumber = "sequence_number"

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

	// Slot X509 CA Slot ID
	Slot = "slot"

	// SPIFFEID tags a SPIFFE ID
	SPIFFEID = "spiffe_id"

	// StartTime tags some start/entry timestamp.
	StartTime = "start_time"

	// Status tags status of call (OK, or some error), or status of some process
	Status = "status"

	// StatusCode tags status codes of call
	StatusCode = "status_code"

	// StatusMessage tags status messages of call
	StatusMessage = "status_message"

	// Subject tags some subject (likely a SPIFFE ID, and likely for a token); should be used
	// with other tags to add clarity
	Subject = "subject"

	// SVIDMapSize is the gauge key for the size of the LRU cache SVID map
	SVIDMapSize = "lru_cache_svid_map_size"

	// SVIDResponseLatency tags latency for SVID response
	SVIDResponseLatency = "svid_response_latency"

	// SVIDSerialNumber tags a certificate serial number
	SVIDSerialNumber = "svid_serial_num"

	// SVIDType tags some type of SVID (eg. X509, JWT)
	SVIDType = "svid_type"

	// SVIDUpdated tags that for some entity the SVID was updated
	SVIDUpdated = "svid_updated"

	// TTL functionality related to a time-to-live field; should be used
	// with other tags to add clarity
	TTL = "ttl"

	// X509 SVID TTL functionality related to a time-to-live field for X509-SVIDs; should be used
	// with other tags to add clarity
	X509SVIDTTL = "x509_svid_ttl"

	// JWT SVID TTL functionality related to a time-to-live field for JWT-SVIDs; should be used
	// with other tags to add clarity
	JWTSVIDTTL = "jwt_svid_ttl"

	// Type tags a type
	Type = "type"

	// TrustDomain tags the name of some trust domain
	TrustDomain = "trust_domain"

	// TrustDomainID tags the ID of some trust domain
	TrustDomainID = "trust_domain_id"

	// Unknown tags some unknown caller, entity, or status
	Unknown = "unknown"

	// Updated tags some entity as updated; should be used
	// with other tags to add clarity
	Updated = "updated"

	// StoreSvid tags if entry is storable
	StoreSvid = "store_svid"

	// Version tags a version
	Version = "version"

	// VersionInfo tags some version information
	VersionInfo = "version_info"

	// WorkloadAttestation tags call of overall workload attestation
	WorkloadAttestation = "workload_attestation"

	// WorkloadAttestor tags call of a workload attestor
	WorkloadAttestor = "workload_attestor"

	// X509 declared X509 SVID type, clarifying metrics
	X509 = "x509"

	// X509AuthoritiesASN1256 tags a X509 authority ASN1 encrypted using SHA256
	X509AuthoritiesASN1SHA256 = "x509_authorities_asn1_sha256"

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

	// BundleManager functionality related to a Bundle manager
	BundleManager = "bundle_manager"

	// BundlesUpdate functionality related to updating bundles
	BundlesUpdate = "bundles_update"

	// CA functionality related to some CA; should be used with other tags
	// to add clarity
	CA = "ca"

	// CAManager functionality related to a CA manager
	CAManager = "ca_manager"

	// Cache functionality related to a cache
	Cache = "cache"

	// Cache type tag
	CacheType = "cache_type"

	// CacheManager functionality related to a cache manager
	CacheManager = "cache_manager"

	// Catalog functionality related to plugin catalog
	Catalog = "catalog"

	// Datastore functionality related to datastore plugin
	Datastore = "datastore"

	// Deleted tags something as deleted
	Deleted = "deleted"

	// Endpoints functionality related to agent/server endpoints
	Endpoints = "endpoints"

	// Entry tag for some stored entry
	Entry = "entry"

	// Event tag some event that has occurred, for a notifier, watcher, listener, etc.
	Event = "event"

	// ExpiringSVIDs tags expiring SVID count/list
	ExpiringSVIDs = "expiring_svids"

	// OutdatedSVIDs tags SVID with outdated attributes count/list
	OutdatedSVIDs = "outdated_svids"

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

	// Limit tags a limit
	Limit = "limit"

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

	// NodeEvent functionality related to a node entity or type being created, updated, or deleted
	NodeEvent = "node_event"

	// Notifier functionality related to some notifying entity; should be used with other tags
	// to add clarity
	Notifier = "notifier"

	// ServerCA functionality related to a server CA; should be used with other tags
	// to add clarity
	ServerCA = "server_ca"

	// Service is the name of the service invoked
	Service = "service"

	// SpireAgent typically the entire spire agent service
	SpireAgent = "spire_agent"

	// SpireServer typically the entire spire server
	SpireServer = "spire_server"

	// SVID functionality related to a SVID; should be used with other tags
	// to add clarity
	SVID = "svid"

	// SVIDRotator functionality related to a SVID rotator
	SVIDRotator = "svid_rotator"

	// SVIDStore tags an SVID store plugin/type (eg. aws_secretsmanager)
	SVIDStore = "svid_store"

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
	// AgentKeyManager attached to all operations related to the Agent KeyManger interface
	AgentKeyManager = "agent_key_manager"

	// AuthorizeCall functionality related to authorizing an incoming call
	AuthorizeCall = "authorize_call"

	// CreateFederatedBundle functionality related to creating a federated bundle
	CreateFederatedBundle = "create_federated_bundle"

	// CreateJoinToken functionality related to creating a join token
	CreateJoinToken = "create_join_token"

	// CreateRegistrationEntry functionality related to creating a registration entry
	CreateRegistrationEntry = "create_registration_entry"

	// CreateRegistrationEntryIfNotExists functionality related to creating a registration entry
	CreateRegistrationEntryIfNotExists = "create_registration_entry_if_not_exists"

	// DebugAPI functionality related to debug endpoints
	DebugAPI = "debug_api"

	// DelegatedIdentityAPI functionality related to delegated identity endpoints
	DelegatedIdentityAPI = "delegated_identity_api"

	// DeleteFederatedBundle functionality related to deleting a federated bundle
	DeleteFederatedBundle = "delete_federated_bundle"

	// DeleteFederatedBundleMode functionality related to deleting federated bundle modes
	DeleteFederatedBundleMode = "delete_federated_bundle_mode"

	// DeleteRegistrationEntry functionality related to deleting a registration entry
	DeleteRegistrationEntry = "delete_registration_entry"

	// EvictAgent functionality related to evicting an agent
	EvictAgent = "evict_agent"

	// FetchBundle functionality related to fetching a CA bundle
	FetchBundle = "fetch_bundle"

	// FetchEntriesUpdates functionality related to fetching entries updates; should be used
	// with other tags to add clarity
	FetchEntriesUpdates = "fetch_entries_updates"

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

	// FetchSVIDsUpdates functionality related to fetching SVIDs updates; should be used
	// with other tags to add clarity
	FetchSVIDsUpdates = "fetch_svids_updates"

	// FetchX509CASVID functionality related to fetching an X509 SVID
	FetchX509CASVID = "fetch_x509_ca_svid"

	// FetchX509SVID functionality related to fetching an X509 SVID
	FetchX509SVID = "fetch_x509_svid"

	// FirstUpdate functionality related to fetching first update in a streaming API.
	FirstUpdate = "first_update"

	// GetNodeSelectors functionality related to getting node selectors
	GetNodeSelectors = "get_node_selectors"

	// CountAgents functionality related to counting agents
	CountAgents = "count_agents"

	// ListAgents functionality related to listing agents
	ListAgents = "list_agents"

	// CountEntries functionality related to counting all registration entries
	CountEntries = "count_entries"

	// ListAllEntriesWithPages functionality related to listing all registration entries with pagination
	ListAllEntriesWithPages = "list_all_entries_with_pages"

	// CountBundles functionality related to counting bundles
	CountBundles = "count_federated_bundles"

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

	// PushJWTKeyUpstream functionality related to pushing a public JWT Key to an upstream server.
	PushJWTKeyUpstream = "push_jwtkey_upstream"

	// SDSAPI functionality related to SDS; should be used with other tags
	// to add clarity
	SDSAPI = "sds_api"

	// ServerKeyManager attached to all operations related to the server KeyManager interface
	ServerKeyManager = "server_key_manager"

	// Store functionality related to SVID Store service
	Store = "store"

	// StreamSecrets functionality related to streaming secrets
	StreamSecrets = "stream_secrets"

	// SubscribeX509SVIDs functionality related to subscribing to X.509 SVIDs.
	SubscribeX509SVIDs = "subscribe_x509_svids"

	// SubsystemName declares field for some subsystem name (an API, module...)
	SubsystemName = "subsystem_name"

	// UpdateFederatedBundle functionality related to updating a federated bundle
	UpdateFederatedBundle = "update_federated_bundle"

	// UpdateRegistrationEntry functionality related to updating a registration entry
	UpdateRegistrationEntry = "update_registration_entry"

	// ValidateJWTSVID functionality related validating a JWT-SVID
	ValidateJWTSVID = "validate_jwt_svid"

	// ValidateJWTSVIDError functionality related to an error validating a JWT-SVID
	ValidateJWTSVIDError = "validate_jwt_svid_error"

	// WorkloadAPI flagging usage of workload API; should be used with other tags
	// to add clarity
	WorkloadAPI = "workload_api"
)
