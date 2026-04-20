package cassandra

import (
	"fmt"
	"time"

	gocql "github.com/apache/cassandra-gocql-driver/v2"
)

const initialConnectionBackoff = 1500 * time.Millisecond

// Configuration is the user-provided Configuration for the Cassandra datastore plugin.
// This type is used to unmarshal the HCL Configuration provided by the user, and is then transformed
// into a runtimeConfiguration which validates and defaults the Configuration values for use at runtime.
// Field-level behavior is documented in the `Configuration` type.
type Configuration struct {
	// The cassandra cluster members.
	// DNS names or IP addresses are both acceptable. At least one host is required.
	// Suggest using the Cassandra seed nodes here, as the client with automatically
	// discover the rest of the cluster from there, but there is no limit to the number
	// of hosts that can be provided here. Each host can optionally include a port number,
	// which will default to 9042 if not specified.
	Hosts []string `hcl:"hosts"`

	// The keyspace name to use for storage. If the keyspace does not exist, the plugin will create it.
	// Generally this is fine for development and testing, but care should be taken when using this in production,
	// as you will likely want to tune the replication strategy and factor to your needs, which the plugin will not
	// mutate once the keyspace is initially created.
	Keyspace string `hcl:"keyspace"`

	// The replication strategy to use for the keyspace, if the plugin is creating it. This can be either
	// "SimpleStrategy" or "NetworkTopologyStrategy". It is highly discouraged to run "SimpleStrategy" in production,
	// as data will inevitably be lost in various failure modes.
	ReplicationStrategy string `hcl:"replication_strategy"`

	// If using "SimpleStrategy" for replication, this will be the replication factor used for the keyspace. If not
	// specified, the plugin will default to a replication factor of 1, which is not suitable for production.
	SimpleStrategyReplicationFactor int `hcl:"simple_strategy_replication_factor"`

	// If using "NetworkTopologyStrategy" for replication, this will be a map of datacenter names to replication factors
	// used for the keyspace. This field is required if "NetworkTopologyStrategy" is used for replication.
	NetworkTopologyStrategyReplicationFactors map[string]int `hcl:"network_topology_strategy_replication_factors"`

	// Username to use when authenticating to Cassandra. If not specified, the plugin will attempt to connect
	// without authenticating.
	Username string `hcl:"username"`

	// Password to use when authenticating to Cassandra. If not specified, the plugin will attempt to connect
	// without authenticating.
	Password string `hcl:"password"`

	// TODO(tjons): should query routing be configurable?

	// The path to the root CA certificate for TLS connections to Cassandra. If this is not specified, TLS will not be
	// used. If this is specified, the plugin will require TLS connections to Cassandra and will verify the Cassandra
	// Node certificate against the root CA.
	//
	// Setting client_key_path and client_cert_path can also affect the behavior of TLS connections.
	RootCAPath string `hcl:"root_ca_path"`

	// The path to the client key for mTLS connections to Cassandra. If this is specified, root_ca_path and
	// client_cert_path must also be specified. When configured, the plugin will require mTLS connections to Cassandra,
	// using the provided client key and certificate for authentication.
	ClientKeyPath string `hcl:"client_key_path"`

	// The path to the client certificate for mTLS connections to Cassandra. If this is specified, client_key_path and
	// root_ca_path must also be specified. When configured, the plugin will require mTLS connections to Cassandra,
	// using the provided client key and certificate for authentication.
	ClientCertPath string `hcl:"client_cert_path"`

	// The number of connections to keep in the connection pool for each host in the Cassandra cluster.
	// If not specified, the plugin default of 10 connections per host will be used. It is highly recommended
	// that you tune this value based on the expected load and performance characteristics of your environment,
	// as the default may not be suitable for production use.
	NumConns int `hcl:"num_conns"`

	// The maximum number of attempts to connect to the Cassandra cluster before giving up and returning an error.
	// The plugin will attempt to connect to the cluster when it starts up, waiting up to the duration specified by
	// ConnectTimeout for each attempt, and will backoff for 1500ms between attempts. If not specified, the plugin will
	// attempt to connect 5 times before giving up.
	MaxConnectionAttempts int `hcl:"max_connection_attempts"`

	// The duration in milliseconds to wait for a connection to the Cassandra cluster before timing out and retrying.
	// If not specified, the plugin will wait 1000ms before timing out and retrying.
	ConnectTimeout time.Duration `hcl:"connect_timeout_ms"`

	// The duration in milliseconds to wait for a read operation to complete before timing out.
	// If not specified, the plugin will wait 1000ms before timing out.
	ReadTimeout time.Duration `hcl:"read_timeout_ms"`

	// The duration in milliseconds to wait for a write operation to complete before timing out.
	// If not specified, the plugin will wait 1000ms before timing out.
	WriteTimeout time.Duration `hcl:"write_timeout_ms"`

	// Whether to skip running database migrations on startup. This will be false by default, and is suitable for development
	// and testing. In production, you may want to run migrations separately and set this to true to avoid any
	// potential issues with running migrations on startup, such as multiple instances of the plugin attempting to run
	// the same migrations at the same time. In any case, the plugin will log any pending migrations on startup,
	// and refuse to start if there are pending migrations and the plugin is configured not to run them.
	SkipMigrations bool `hcl:"skip_migrations"`

	// To determine whether or not there are more results to be paginated through, the Cassandra plugin needs to "peek"
	// at the next page of results by fetching a single item from it. This can be unnecessary drag on performance, so
	// this option allows you to disable that behavior. If you disable pagination peeking, the plugin will generally
	// perform better when paginating through large result sets, but will not accurately determine whether or not the
	// current page is the last page, and will always assume that there is another page of results after the current one.
	DisablePaginationPeeking bool `hcl:"disable_pagination_peeking"`

	// Default consistency levels for read operations. Acceptable values are:
	// "ONE", "LOCAL_QUORUM", "EACH_QUORUM", "QUORUM", or "ALL". If not specified, the default
	// consistency level for reads will be "LOCAL_QUORUM". For more information
	// on Cassandra consistency levels, see
	// https://cassandra.apache.org/doc/latest/cassandra/architecture/dynamo.html#tunable-consistency.
	ReadConsistency string `hcl:"read_consistency"`

	// Default consistency levels for write operations. Acceptable values are:
	// - "ONE"
	// - "LOCAL_QUORUM"
	// - "QUORUM"
	// - "EACH_QUORUM"
	// - "ALL"
	// If not specified, the default consistency level for writes will be "LOCAL_QUORUM".
	// For more information on Cassandra consistency levels, see
	// https://cassandra.apache.org/doc/latest/cassandra/architecture/dynamo.html#tunable-consistency.
	WriteConsistency string `hcl:"write_consistency"`

	// Used to control the log level of the underlying Cassandra database driver, not the plugin itself.
	// Acceptable values are "DEBUG", "INFO", "WARN", "ERROR", and "OFF". 
	// If not specified, the driver will use its default log level.
	DriverLogLevel string `hcl:"driver_log_level"`
}

func validateConsistencyLevel(level string) error {
	switch level {
	case "ONE", "LOCAL_QUORUM", "QUORUM", "EACH_QUORUM", "ALL":
		return nil
	default:
		return fmt.Errorf("invalid consistency level: %s", level)
	}
}

type ReplicationStrategy string

const (
	SimpleStrategy          ReplicationStrategy = "SimpleStrategy"
	NetworkTopologyStrategy ReplicationStrategy = "NetworkTopologyStrategy"
)

// runtimeConfiguration is the parsed, validated and defaulted configuration that is used at runtime.
// It's derived from the user-provided `configuration` type, but with all fields set to their final values.
// Field-level behavior is documented in the `configuration` type.
type runtimeConfiguration struct {
	ReadConsistency                           gocql.Consistency
	WriteConsistency                          gocql.Consistency
	Keyspace                                  string
	Hosts                                     []string
	DisablePaginationPeeking                  bool
	ConnectTimeout                            time.Duration
	ReadTimeout                               time.Duration
	WriteTimeout                              time.Duration
	MaxConnectionAttempts                     int
	RunMigrations                             bool
	ReplicationStrategy                       ReplicationStrategy
	SimpleStrategyReplicationFactor           int
	NetworkTopologyStrategyReplicationFactors map[string]int
	Username                                  string
	Password                                  string
	DriverLogLevel                            driverLogLevel
	TLSConfig                                 *tlsConfig
	NumConns                                  int
}

type tlsConfig struct {
	RootCAPath     string
	ClientKeyPath  string
	ClientCertPath string
}

func (t tlsConfig) RequireMTLS() bool {
	return t.RequireTLS() && t.ClientKeyPath != "" && t.ClientCertPath != ""
}

func (t tlsConfig) RequireTLS() bool {
	return t.RootCAPath != ""
}

func (r *runtimeConfiguration) FromUserConfig(cfg *Configuration) error {
	r.Hosts = cfg.Hosts
	r.Keyspace = cfg.Keyspace
	r.DisablePaginationPeeking = cfg.DisablePaginationPeeking
	r.ConnectTimeout = time.Duration(cfg.ConnectTimeout) * time.Millisecond
	r.ReadTimeout = time.Duration(cfg.ReadTimeout) * time.Millisecond
	r.WriteTimeout = time.Duration(cfg.WriteTimeout) * time.Millisecond
	r.MaxConnectionAttempts = cfg.MaxConnectionAttempts
	r.RunMigrations = !cfg.SkipMigrations
	r.SimpleStrategyReplicationFactor = cfg.SimpleStrategyReplicationFactor
	r.NetworkTopologyStrategyReplicationFactors = cfg.NetworkTopologyStrategyReplicationFactors
	r.Username = cfg.Username
	r.Password = cfg.Password
	r.DriverLogLevel = driverLogLevel(cfg.DriverLogLevel) // TODO(tjons): validate that this is a correct level
	r.TLSConfig = &tlsConfig{
		RootCAPath:     cfg.RootCAPath,
		ClientKeyPath:  cfg.ClientKeyPath,
		ClientCertPath: cfg.ClientCertPath,
	}
	r.NumConns = cfg.NumConns
	if r.NumConns == 0 {
		r.NumConns = 10
	}

	if cfg.ReplicationStrategy == "" {
		r.ReplicationStrategy = SimpleStrategy
	} else {
		switch cfg.ReplicationStrategy {
		case "SimpleStrategy":
			r.ReplicationStrategy = SimpleStrategy
		case "NetworkTopologyStrategy":
			r.ReplicationStrategy = NetworkTopologyStrategy
		default:
			return fmt.Errorf("invalid replication strategy: %s", cfg.ReplicationStrategy)
		}
	}

	if cfg.SimpleStrategyReplicationFactor == 0 {
		r.SimpleStrategyReplicationFactor = 1
	}

	if cfg.MaxConnectionAttempts == 0 {
		r.MaxConnectionAttempts = 5
	}

	if cfg.ConnectTimeout == 0 {
		r.ConnectTimeout = 1000 * time.Millisecond
	}

	if cfg.ReadTimeout == 0 {
		r.ReadTimeout = 1000 * time.Millisecond
	}

	if cfg.WriteTimeout == 0 {
		r.WriteTimeout = 1000 * time.Millisecond
	}

	if cfg.ReadConsistency == "" {
		cfg.ReadConsistency = gocql.LocalQuorum.String()
	}
	if err := validateConsistencyLevel(cfg.ReadConsistency); err != nil {
		return fmt.Errorf("invalid read consistency level: %w", err)
	}
	r.ReadConsistency = gocql.ParseConsistency(cfg.ReadConsistency)

	if cfg.WriteConsistency == "" {
		cfg.WriteConsistency = gocql.LocalQuorum.String()
	}
	if err := validateConsistencyLevel(cfg.WriteConsistency); err != nil {
		return fmt.Errorf("invalid write consistency level: %w", err)
	}
	r.WriteConsistency = gocql.ParseConsistency(cfg.WriteConsistency)

	if r.Username != "" || r.Password != "" {
		if r.Username == "" {
			return fmt.Errorf("username must be provided if password is provided")
		}

		if r.Password == "" {
			return fmt.Errorf("password must be provided if username is provided")
		}
	}

	return nil
}
