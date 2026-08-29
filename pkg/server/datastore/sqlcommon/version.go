package sqlcommon

const (
	SQLiteVersionQuery   = "SELECT sqlite_version()"
	PostgresVersionQuery = "SHOW server_version"
	MySQLVersionQuery    = "SELECT VERSION()"
)
