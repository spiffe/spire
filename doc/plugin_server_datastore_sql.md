# Server plugin: DataStore "sql"

The `sql` plugin implements a sql based storage option for the SPIRE server using SQLite and PostgreSQL databases.

| Configuration     | Description                                |
| ------------------| ------------------------------------------ |
| database_type     | database type                              |
| connection_string | connection string                          |

The plugin defaults to an in-memory database and any information in the data store is lost on restart.

## Database configurations

### `database_type = "sqlite3"`
Save database in file
```
connection_string="DATABASE_FILE.db"
```

Save database in memory
```
connection_string=":memory:"
```

### `database_type = "postgres"`

The `connection_string` for the PostreSQL database connection consists of the number of configuration options separated by spaces.

#### example
```
connection_string="dbname=postgres user=postgres password=password host=localhost sslmode=disable"
```

#### Configuration Options
* dbname - The name of the database to connect to
* user - The user to sign in as
* password - The user's password
* host - The host to connect to. Values that start with / are for unix
  domain sockets. (default is localhost)
* port - The port to bind to. (default is 5432)
* sslmode - Whether or not to use SSL (default is require, this is not
  the default for libpq)
* fallback_application_name - An application_name to fall back to if one isn't provided.
* connect_timeout - Maximum wait for connection, in seconds. Zero or
  not specified means wait indefinitely.
* sslcert - Cert file location. The file must contain PEM encoded data.
* sslkey - Key file location. The file must contain PEM encoded data.
* sslrootcert - The location of the root certificate file. The file
  must contain PEM encoded data.

#### Valid sslmode configurations
* disable - No SSL
* require - Always SSL (skip verification)
* verify-ca - Always SSL (verify that the certificate presented by the
  server was signed by a trusted CA)
* verify-full - Always SSL (verify that the certification presented by
  the server was signed by a trusted CA and the server host name
  matches the one in the certificate)

