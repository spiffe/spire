package cassandra

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	gocql "github.com/apache/cassandra-gocql-driver/v2"
	"github.com/spiffe/spire/pkg/server/datastore/cassandra/migrations"
)

func (p *Plugin) ensureKeyspaceExists(ctx context.Context, config *runtimeConfiguration) error {
	bootstrapCluster := gocql.NewCluster(config.Hosts...)

	if config.Username != "" && config.Password != "" {
		bootstrapCluster.Authenticator = gocql.PasswordAuthenticator{
			Username: config.Username,
			Password: config.Password,
		}
	}

	bootstrapCluster.Consistency = gocql.One
	bootstrapCluster.Logger = &wrappedLogger{logger: p.log, level: config.DriverLogLevel}

	if config.TLSConfig.RequireMTLS() {
		// Verify that the files can be read before attempting to use them for TLS configuration, to fail fast if there are any issues with the provided paths or files.
		clientCert, err := os.ReadFile(config.TLSConfig.ClientCertPath)
		if err != nil {
			return fmt.Errorf("unable to read client certificate: %w", err)
		}
		if len(clientCert) == 0 {
			return fmt.Errorf("client certificate file is empty: %s", config.TLSConfig.ClientCertPath)
		}

		clientKey, err := os.ReadFile(config.TLSConfig.ClientKeyPath)
		if err != nil {
			return fmt.Errorf("unable to read client key: %w", err)
		}
		if len(clientKey) == 0 {
			return fmt.Errorf("client key file is empty: %s", config.TLSConfig.ClientKeyPath)
		}

		rootCA, err := os.ReadFile(config.TLSConfig.RootCAPath)
		if err != nil {
			return fmt.Errorf("unable to read root CA certificate: %w", err)
		}
		if len(rootCA) == 0 {
			return fmt.Errorf("root CA certificate file is empty: %s", config.TLSConfig.RootCAPath)
		}

		bootstrapCluster.SslOpts = &gocql.SslOptions{
			EnableHostVerification: true,
			CertPath:               config.TLSConfig.ClientCertPath,
			KeyPath:                config.TLSConfig.ClientKeyPath,
			CaPath:                 config.TLSConfig.RootCAPath,
		}
	} else if config.TLSConfig.RequireTLS() {
		// Verify that the file can be read before attempting to use it for TLS configuration, to fail fast if there are any issues with the provided path or file.
		rootCA, err := os.ReadFile(config.TLSConfig.RootCAPath)
		if err != nil {
			return fmt.Errorf("unable to read root CA certificate: %w", err)
		}
		if len(rootCA) == 0 {
			return fmt.Errorf("root CA certificate file is empty: %s", config.TLSConfig.RootCAPath)
		}

		bootstrapCluster.SslOpts = &gocql.SslOptions{
			EnableHostVerification: true,
			CaPath:                 config.TLSConfig.RootCAPath,
		}
	}

	bootstrapSession, err := bootstrapCluster.CreateSession()
	if err != nil {
		return err
	}
	defer bootstrapSession.Close()

	const listKeyspacesQuery = "SELECT keyspace_name FROM system_schema.keyspaces"
	iter := bootstrapSession.Query(listKeyspacesQuery).IterContext(ctx)

	var keyspaceName string
	for iter.Scan(&keyspaceName) {
		if keyspaceName == config.Keyspace {
			return nil
		}
	}

	if err := p.createKeyspace(ctx, config, bootstrapSession); err != nil {
		return err
	}

	return nil
}

func (p *Plugin) createKeyspace(ctx context.Context, config *runtimeConfiguration, session *gocql.Session) error {
	queryBuilder := strings.Builder{}
	// use IF NOT EXISTS here because in an HA setup, multiple SPIRE server replicas
	// may attempt to create the keyspace simultaneously.
	queryBuilder.WriteString("CREATE KEYSPACE IF NOT EXISTS ")
	queryBuilder.WriteString(config.Keyspace)
	queryBuilder.WriteString(" WITH REPLICATION = {'class': '")

	switch config.ReplicationStrategy {
	case SimpleStrategy:
		queryBuilder.WriteString("SimpleStrategy', 'replication_factor': ")
		queryBuilder.WriteString(strconv.Itoa(config.SimpleStrategyReplicationFactor))
	case NetworkTopologyStrategy:
		addNetworkTopologyStrategyReplicationOptions(&queryBuilder, config.NetworkTopologyStrategyReplicationFactors)
	}

	queryBuilder.WriteString("}")
	query := queryBuilder.String()

	if err := session.Query(query).ExecContext(ctx); err != nil {
		return fmt.Errorf("failed to create keyspace: %w", err)
	}

	return nil
}

func addNetworkTopologyStrategyReplicationOptions(queryBuilder *strings.Builder, datacenters map[string]int) {
	first := true
	queryBuilder.WriteString("NetworkTopologyStrategy', ")

	for dc, rf := range datacenters {
		if !first {
			queryBuilder.WriteString(", ")
		}
		queryBuilder.WriteString("'")
		queryBuilder.WriteString(dc)
		queryBuilder.WriteString("': ")
		queryBuilder.WriteString(strconv.Itoa(rf))

		first = false
	}

}

func (p *Plugin) applyMigrations(session *gocql.Session) error {
	return migrations.RunMigrations(context.Background(), p.cfg.Keyspace, session, migrations.Migrations)
}
