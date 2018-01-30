# Server plugin: datastore-sqlite

The `datastore-sqlite` stores registration entries, selector maps, and attested nodes in a
SQLite database.

The plugin accepts the following configuration options:

| Configuration | Description                                    |
| ------------- | ---------------------------------------------- |
| file_name     | File path used to persist the database to disk |

If a file path is not configured, the plugin will default to an in-memory database and any
information in the data store is lost on restart.
