# Server plugin: DataStore "sql"

The `sql` plugin implements a sql based storage option for the SPIRE server using SQLite, PostgreSQL or MySQL databases.

| Configuration        | Description                                                                |
| ---------------------| -------------------------------------------------------------------------- |
| database_type        | database type                                                              |
| connection_string    | connection string                                                          |
| ro_connection_string | read-only connection string, used for read-only queries if set             |
| root_ca_path         | Path to Root CA bundle (MySQL only)                                        |
| client_cert_path     | Path to client certificate (MySQL only)                                    |
| client_key_path      | Path to private key for client certificate (MySQL only)                    |
| max_open_conns       | The maximum number of open db connections (default: unlimited)             |
| max_idle_conns       | The maximum number of idle connections in the pool (default: 2)            |
| conn_max_lifetime    | The maximum amount of time a connection may be reused (default: unlimited) |
| disable_migration    | True to disable auto-migration functionality. Use of this flag allows finer control over when datastore migrations occur and coordination of the migration of a datastore shared with a SPIRE Server cluster. Only available for databases from SPIRE Code version 0.9.0 or later. |

The plugin defaults to an in-memory database and any information in the data store is lost on restart.

For more information on the `max_open_conns`, `max_idle_conns`, and `conn_max_lifetime`, refer to the
documentation for the Go [`database/sql`](https://golang.org/pkg/database/sql/#DB) package.

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

#### Sample configuration

```
    DataStore "sql" {
        plugin_data {
            database_type = "sqlite3"
            connection_string = "./.data/datastore.sqlite3"
            ro_connection_string = "./.data/datastore.sqlite3"
        }
    }
```

### `database_type = "postgres"`

The `connection_string` for the PostreSQL database connection consists of the number of configuration options separated by spaces.

#### example
```
connection_string="dbname=postgres user=postgres password=password host=localhost sslmode=disable"
```
```
ro_connection_string="ro_username:password@tcp(localhost:3308)/dbname?parseTime=true"
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

#### Sample configuration

```
    DataStore "sql" {
        plugin_data {
            database_type = "postgres"
            connection_string = "dbname=spire_development user=spire host=127.0.0.1 sslmode=disable"
        }
    }
```

### `database_type = "mysql"`

The `connection_string` for the MySQL database connection consists of the number of configuration options (optional parts marked by square brackets):

````
username[:password]@][protocol[(address)]]/dbname[?param1=value1&...&paramN=valueN]
````

#### example
```
connection_string="username:password@tcp(localhost:3306)/dbname?parseTime=true"
```

Consult the [MySQL driver repository](https://github.com/go-sql-driver/mysql#usage) for more `connection_string` options.

#### Configuration Options
* dbname - The name of the database to connect to
* username - The user to sign in as
* password - The user's password
* address - The host to connect to. Values that start with / are for unix
  domain sockets. (default is localhost)

If you need to use custom Root CA, just specify `root_ca_path` in the plugin config. Similarly, if you need to use client certificates, specify `client_key_path` and `client_cert_path`. Other options can be configured via [tls](https://github.com/go-sql-driver/mysql#tls) params in the `connection_string` options.

#### Sample configuration

```
    DataStore "sql" {
        plugin_data {
            database_type = "mysql"
            connection_string = "spire:@tcp(127.0.0.1)/spire_development?parseTime=true"
        }
    }
```
