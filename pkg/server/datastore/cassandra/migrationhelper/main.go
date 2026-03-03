package main

import (
	"context"
	"log"

	gocql "github.com/apache/cassandra-gocql-driver/v2"
	"github.com/spiffe/spire/pkg/server/datastore/cassandra/migrations"
)

func main() {
	ctx := context.Background()
	s := gocql.NewCluster("localhost:9044")
	sess, err := s.CreateSession()
	if err != nil {
		log.Fatalf("Failed to connect to Cassandra: %s", err.Error())
	}
	defer sess.Close()

	if err := sess.Query("CREATE KEYSPACE IF NOT EXISTS spire WITH replication = {'class': 'SimpleStrategy', 'replication_factor': '1'}").ExecContext(ctx); err != nil {
		log.Fatalf("Failed to create keyspace: %s", err.Error())
	}

	if err := migrations.RunMigrations(ctx, "spire", sess, migrations.Migrations); err != nil {
		log.Fatalf("Migrations failed to execute: %s", err.Error())
	}
}
