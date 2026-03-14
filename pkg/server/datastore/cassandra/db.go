package cassandra

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"

	gocql "github.com/apache/cassandra-gocql-driver/v2"
	"github.com/sirupsen/logrus"
	"github.com/tjons/cassandra-toolbox/qb"
)

type cassandraDB struct {
	cfg     *runtimeConfiguration
	rwLock  *sync.Mutex
	log     logrus.FieldLogger
	session *gocql.Session
}

func (c *cassandraDB) WriteQuery(wq qb.QueryBuilder) *gocql.Query {
	stmt, _ := wq.Build()

	query := c.session.Query(stmt, wq.QueryValues()...)
	query.Consistency(c.cfg.WriteConsistency)

	return query
}

func (c *cassandraDB) ReadQuery(rq qb.QueryBuilder) *gocql.Query {
	stmt, _ := rq.Build()

	query := c.session.Query(stmt, rq.QueryValues()...)
	query.Consistency(c.cfg.ReadConsistency)

	return query
}

func (p *Plugin) openConnections(ctx context.Context, config *runtimeConfiguration) error {
	if p.cfg == nil {
		return errors.New("configuration not set")
	}

	return p.openConnection(ctx, config)
}

func (p *Plugin) openConnection(ctx context.Context, config *runtimeConfiguration) (err error) {
	p.rwLock.Lock()
	defer p.rwLock.Unlock()

	if err := p.ensureKeyspaceExists(ctx, config); err != nil {
		return err
	}

	db := &cassandraDB{
		cfg: config,
		log: p.log,
	}
	db.session, err = p.createSession(config)
	if err != nil {
		return fmt.Errorf("failed to create Cassandra session: %w", err)
	}
	p.db = db

	// TODO(tjons): use this to split the execution of the migrations from checking if the migrations need to be run.
	// We want to refuse to start if we are not allowed to run migrations and there are pending migrations.
	if config.RunMigrations {
		p.log.Info("Running Cassandra migrations...")
		if err := p.applyMigrations(p.db.session); err != nil {
			return err
		}
		p.log.Info("Cassandra migrations complete.")
	}

	return nil
}

func (p *Plugin) createSession(config *runtimeConfiguration) (*gocql.Session, error) {
	clusterConfig := gocql.NewCluster(config.Hosts...)
	clusterConfig.ConnectTimeout = config.ConnectTimeout
	clusterConfig.NumConns = config.NumConns
	clusterConfig.Timeout = config.ReadTimeout
	clusterConfig.WriteTimeout = config.WriteTimeout
	clusterConfig.Keyspace = config.Keyspace
	clusterConfig.Consistency = config.ReadConsistency
	clusterConfig.Logger = &wrappedLogger{logger: p.log, level: config.DriverLogLevel}

	if config.Username != "" && config.Password != "" {
		clusterConfig.Authenticator = gocql.PasswordAuthenticator{
			Username: config.Username,
			Password: config.Password,
		}
	} else {
		p.log.Warn("No authentication configured for Cassandra. This is not recommended for production environments.")
	}

	if config.TLSConfig.RequireMTLS() {
		// Verify that the files can be read before attempting to use them for TLS configuration, to fail fast if there are any issues with the provided paths or files.
		clientCert, err := os.ReadFile(config.TLSConfig.ClientCertPath)
		if err != nil {
			return nil, fmt.Errorf("unable to read client certificate: %w", err)
		}
		if len(clientCert) == 0 {
			return nil, fmt.Errorf("client certificate file is empty: %s", config.TLSConfig.ClientCertPath)
		}

		clientKey, err := os.ReadFile(config.TLSConfig.ClientKeyPath)
		if err != nil {
			return nil, fmt.Errorf("unable to read client key: %w", err)
		}
		if len(clientKey) == 0 {
			return nil, fmt.Errorf("client key file is empty: %s", config.TLSConfig.ClientKeyPath)
		}

		rootCA, err := os.ReadFile(config.TLSConfig.RootCAPath)
		if err != nil {
			return nil, fmt.Errorf("unable to read root CA certificate: %w", err)
		}
		if len(rootCA) == 0 {
			return nil, fmt.Errorf("root CA certificate file is empty: %s", config.TLSConfig.RootCAPath)
		}

		clusterConfig.SslOpts = &gocql.SslOptions{
			EnableHostVerification: true,
			CertPath:               config.TLSConfig.ClientCertPath,
			KeyPath:                config.TLSConfig.ClientKeyPath,
			CaPath:                 config.TLSConfig.RootCAPath,
		}
	} else if config.TLSConfig.RequireTLS() {
		// Verify that the file can be read before attempting to use it for TLS configuration, to fail fast if there are any issues with the provided path or file.
		rootCA, err := os.ReadFile(config.TLSConfig.RootCAPath)
		if err != nil {
			return nil, fmt.Errorf("unable to read root CA certificate: %w", err)
		}
		if len(rootCA) == 0 {
			return nil, fmt.Errorf("root CA certificate file is empty: %s", config.TLSConfig.RootCAPath)
		}

		clusterConfig.SslOpts = &gocql.SslOptions{
			EnableHostVerification: true,
			CaPath:                 config.TLSConfig.RootCAPath,
		}
	}

	return clusterConfig.CreateSession()
}
