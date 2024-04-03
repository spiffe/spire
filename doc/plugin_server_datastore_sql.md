# Server plugin: DataStore "sql"

The `sql` plugin implements SQL based data storage for the SPIRE server using SQLite, PostgreSQL or MySQL databases.

| Configuration        | Description                                                                                                                                                                                                                                                                        |
|----------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| database_type        | database type                                                                                                                                                                                                                                                                      |
| connection_string    | connection string                                                                                                                                                                                                                                                                  |
| ro_connection_string | [Read Only connection](#read-only-connection)                                                                                                                                                                                                                                      |
| root_ca_path         | Path to Root CA bundle (MySQL only)                                                                                                                                                                                                                                                |
| client_cert_path     | Path to client certificate (MySQL only)                                                                                                                                                                                                                                            |
| client_key_path      | Path to private key for client certificate (MySQL only)                                                                                                                                                                                                                            |
| max_open_conns       | The maximum number of open db connections (default: 100)                                                                                                                                                                                                                     |
| max_idle_conns       | The maximum number of idle connections in the pool (default: 2)                                                                                                                                                                                                                    |
| conn_max_lifetime    | The maximum amount of time a connection may be reused (default: unlimited)                                                                                                                                                                                                         |
| disable_migration    | True to disable auto-migration functionality. Use of this flag allows finer control over when datastore migrations occur and coordination of the migration of a datastore shared with a SPIRE Server cluster. Only available for databases from SPIRE Code version 0.9.0 or later. |

For more information on the `max_open_conns`, `max_idle_conns`, and `conn_max_lifetime`, refer to the
documentation for the Go [`database/sql`](https://golang.org/pkg/database/sql/#DB) package.

## Database configurations

### `database_type = "sqlite3"`

Save database in file:

```hcl
connection_string="DATABASE_FILE.db"
```

Save database in memory:

```hcl
connection_string="file:memdb?mode=memory&cache=shared"
```

If you are compiling SPIRE from source, please see [SQLite and CGO](#sqlite-and-cgo) for additional information.

#### Sample configuration

```hcl
    DataStore "sql" {
        plugin_data {
            database_type = "sqlite3"
            connection_string = "./.data/datastore.sqlite3"
        }
    }
```

### `database_type = "postgres"`

The `connection_string` for the PostgreSQL database connection consists of the number of configuration options separated by spaces.

For example:

```hcl
connection_string="dbname=postgres user=postgres password=password host=localhost sslmode=disable"
```

Consult the [lib/pq driver documentation](https://pkg.go.dev/github.com/lib/pq#hdr-Connection_String_Parameters) for more `connection_string` options.

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

```hcl
    DataStore "sql" {
        plugin_data {
            database_type = "postgres"
            connection_string = "dbname=spire_development user=spire host=127.0.0.1 sslmode=disable"
        }
    }
```

### `database_type = "mysql"`

The `connection_string` for the MySQL database connection consists of the number of configuration options (optional parts marked by square brackets):

```text
username[:password]@][protocol[(address)]]/dbname[?param1=value1&...&paramN=valueN]
```

For example:

```hcl
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

```hcl
    DataStore "sql" {
        plugin_data {
            database_type = "mysql"
            connection_string = "spire:@tcp(127.0.0.1)/spire_development?parseTime=true"
        }
    }
```

### IAM Authentication

Identity and Access Management (IAM) authentication allows for secure authentication to databases hosted on cloud services. Unlike traditional methods, it uses an authentication token instead of a password. When using IAM authentication, it is required to exclude the password from the connection string.

The `database_type` configuration allows specifying the type of database with IAM authentication support. The configuration always follows this structure:

```hcl
    database_type "dbtype-with-iam-support" {
        setting_1 = "value-1"
        setting_2 = "value-2"
        ...
    }
```

_Note: Replace `dbtype-with-iam-support` with the specific database type that supports IAM authentication._

Supported IAM authentication database types include:

#### "aws_postgres"

For PostgreSQL databases on AWS RDS using IAM authentication. The `region` setting is mandatory, specifying the AWS service region.

This is the complete list of configuration options under the `database_type` setting when `aws_postgres` is set:

| Configuration     | Description                           | Required                                                               | Default                                             |
|-------------------|---------------------------------------|------------------------------------------------------------------------|-----------------------------------------------------|
| access_key_id     | AWS access key id.                    | Required only if AWS_ACCESS_KEY_ID environment variable is not set.    | Value of AWS_ACCESS_KEY_ID environment variable.    |
| secret_access_key | AWS secret access key.                | Required only if AWS_SECRET_ACCESSKEY environment variable is not set. | Value of AWS_SECRET_ACCESSKEY environment variable. |
| region            | AWS region of the database.           | Yes.                                                                   |                                                     |

Settings of the [`postgres`](#database_type--postgres) database type also apply here.

##### Sample configuration

```hcl
    DataStore "sql" {
        plugin_data {
            database_type "aws_postgres" {
                region = "us-east-2"
            }
            connection_string = "dbname=spire user=test_user host=spire-test.example.us-east-2.rds.amazonaws.com port=5432 sslmode=require"
        }
   }
```

#### "aws_mysql"

For MySQL databases on AWS RDS using IAM authentication. The `region` setting is required.

This is the complete list of configuration options under the `database_type` setting when `aws_mysql` is set:

| Configuration     | Description                           | Required                                                               | Default                                             |
|-------------------|---------------------------------------|------------------------------------------------------------------------|-----------------------------------------------------|
| access_key_id     | AWS access key id.                    | Required only if AWS_ACCESS_KEY_ID environment variable is not set.    | Value of AWS_ACCESS_KEY_ID environment variable.    |
| secret_access_key | AWS secret access key.                | Required only if AWS_SECRET_ACCESSKEY environment variable is not set. | Value of AWS_SECRET_ACCESSKEY environment variable. |
| region            | AWS region of the database.           | Yes.                                                                   |                                                     |

Settings of the [`mysql`](#database_type--mysql) database type also apply here.

##### Sample configuration

```hcl
    DataStore "sql" {
        plugin_data {
            database_type "aws_mysql" {
                region = "us-east-2"
            }
            connection_string="test_user:@tcp(spire-test.example.us-east-2.rds.amazonaws.com:3306)/spire?parseTime=true&allowCleartextPasswords=1&tls=true"
        }
    }
```

#### Read Only connection

Read Only connection will be used when the optional `ro_connection_string` is set. The formatted string takes the same form as connection_string. This option is not applicable for SQLite3.

## SQLite and CGO

SQLite support requires the use of CGO. This is not a concern for users downloading SPIRE or using the official SPIRE container images. However, if you are building SPIRE from the source code, please note that compiling SPIRE without CGO (e.g. `CGO_ENABLED=0`) will disable SQLite support.
