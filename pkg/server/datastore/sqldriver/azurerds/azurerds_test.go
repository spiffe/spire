package azurerds

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"database/sql/driver"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	fakeSQLDriverName  = "fake-azure-sql-driver"
	token              = "fake-entra-id-access-token"
	postgresConnString = "dbname=postgres user=postgres host=the-host sslmode=require"
	mysqlConnString    = "the-user@tcp(the-host:3306)/spire?parseTime=true&allowCleartextPasswords=1&tls=true"
)

var fakeSQLDriverWrapper = &sqlDriverWrapper{
	sqlDriver:    &fakeSQLDriver{},
	tokenBuilder: &fakeTokenBuilder{},
	tokensMap:    make(tokens),
}

func init() {
	sql.Register(fakeSQLDriverName, fakeSQLDriverWrapper)
}

func TestAzureRDS(t *testing.T) {
	// Some GitHub runners may have populated the PGPASSWORD environment
	// variable. Have an empty value during the test.
	t.Setenv("PGPASSWORD", "")

	testCases := []struct {
		name          string
		config        *Config
		tokenProvider *fakeTokenBuilder
		expectedError string
	}{
		{
			name: "postgres - success",
			config: &Config{
				DriverName: PostgresDriverName,
				ConnString: postgresConnString,
			},
			tokenProvider: &fakeTokenBuilder{
				authToken: token,
			},
		},
		{
			name: "postgres - password already present",
			config: &Config{
				DriverName: PostgresDriverName,
				ConnString: "password=the-password",
			},
			tokenProvider: &fakeTokenBuilder{
				authToken: token,
			},
			expectedError: "unexpected password in connection string for Microsoft Entra ID authentication",
		},
		{
			name: "postgres - invalid connection string",
			config: &Config{
				DriverName: PostgresDriverName,
				ConnString: "not-valid!",
			},
			tokenProvider: &fakeTokenBuilder{
				authToken: token,
			},
			expectedError: "could not parse connection string: cannot parse `not-valid!`: failed to parse as keyword/value (invalid keyword/value)",
		},
		{
			name: "build auth token error",
			config: &Config{
				DriverName: PostgresDriverName,
				ConnString: postgresConnString,
			},
			tokenProvider: &fakeTokenBuilder{
				authToken: token,
				err:       errors.New("ohno"),
			},
			expectedError: "could not get authentication token: failed to build authentication token: ohno",
		},
		{
			name: "mysql - success",
			config: &Config{
				DriverName: MySQLDriverName,
				ConnString: mysqlConnString,
			},
			tokenProvider: &fakeTokenBuilder{
				authToken: token,
			},
		},
		{
			name: "mysql - password already present",
			config: &Config{
				DriverName: MySQLDriverName,
				ConnString: "the-user:the-password@tcp(the-host:3306)/spire?parseTime=true",
			},
			tokenProvider: &fakeTokenBuilder{
				authToken: token,
			},
			expectedError: "unexpected password in connection string for Microsoft Entra ID authentication",
		},
		{
			name: "mysql - invalid connection string",
			config: &Config{
				DriverName: MySQLDriverName,
				ConnString: "not-valid!",
			},
			tokenProvider: &fakeTokenBuilder{
				authToken: token,
			},
			expectedError: "could not parse connection string: invalid DSN: missing the slash separating the database name",
		},
		{
			name: "unknown driver",
			config: &Config{
				DriverName: "unknown",
			},
			tokenProvider: &fakeTokenBuilder{
				authToken: token,
			},
			expectedError: "driver \"unknown\" is not supported",
		},
		{
			name:   "no driver",
			config: &Config{},
			tokenProvider: &fakeTokenBuilder{
				authToken: token,
			},
			expectedError: "missing driver name",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			dsn, err := testCase.config.FormatDSN()
			require.NoError(t, err)

			fakeSQLDriverWrapper.tokenBuilder = testCase.tokenProvider
			fakeSQLDriverWrapper.tokensMap = make(tokens)

			db, err := gorm.Open(fakeSQLDriverName, dsn)
			if testCase.expectedError != "" {
				require.EqualError(t, err, testCase.expectedError)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, db)
		})
	}
}

func TestCacheToken(t *testing.T) {
	// Some GitHub runners may have populated the PGPASSWORD environment
	// variable. Have an empty value during the test.
	t.Setenv("PGPASSWORD", "")

	config := &Config{
		DriverName: PostgresDriverName,
		ConnString: postgresConnString,
	}
	dsn, err := config.FormatDSN()
	require.NoError(t, err)

	initialTime := time.Now().UTC()
	ttl := time.Minute * 15

	// Set a first token to be always returned by the token builder.
	fakeSQLDriverWrapper.tokenBuilder = &fakeTokenBuilder{
		authToken: "first-token",
		expiresOn: initialTime.Add(ttl),
	}
	fakeSQLDriverWrapper.tokensMap = make(tokens)

	// There should be no token for this dsn yet.
	require.Empty(t, fakeSQLDriverWrapper.tokensMap[dsn])

	// Calling to Open should cache the first token for the dsn.
	db, err := gorm.Open(fakeSQLDriverName, dsn)
	require.NoError(t, err)
	require.NotNil(t, db)

	token, err := fakeSQLDriverWrapper.tokensMap[dsn].getAuthToken(context.Background(), config, fakeSQLDriverWrapper.tokenBuilder)
	require.NoError(t, err)
	require.Equal(t, "first-token", token)

	// We will now test that we don't call the token builder if we have a
	// valid (not expired) token that we can use.
	fakeSQLDriverWrapper.tokenBuilder = &fakeTokenBuilder{
		authToken: "second-token",
		expiresOn: initialTime.Add(ttl),
	}

	// Advance the clock just a few seconds.
	nowFunc = func() time.Time { return initialTime.Add(time.Second * 15) }

	db, err = gorm.Open(fakeSQLDriverName, dsn)
	require.NoError(t, err)
	require.NotNil(t, db)

	token, err = fakeSQLDriverWrapper.tokensMap[dsn].getAuthToken(context.Background(), config, fakeSQLDriverWrapper.tokenBuilder)
	require.NoError(t, err)
	require.Equal(t, "first-token", token)

	// Now make the first token expire (accounting for clock skew), and
	// confirm the token builder is called again for a new token.
	nowFunc = func() time.Time { return initialTime.Add(ttl).Add(-clockSkew) }

	db, err = gorm.Open(fakeSQLDriverName, dsn)
	require.NoError(t, err)
	require.NotNil(t, db)

	token, err = fakeSQLDriverWrapper.tokensMap[dsn].getAuthToken(context.Background(), config, fakeSQLDriverWrapper.tokenBuilder)
	require.NoError(t, err)
	require.Equal(t, "second-token", token)
}

// TestAuthTokenConcurrentAccess exercises the same *authToken from many
// goroutines at once, the way database/sql does when it grows a connection
// pool for a single DSN (sqlDriverWrapper.tokensMap hands out one *authToken
// per DSN, shared by every connection to it). Run with -race: without the
// mutex in authToken, this reliably trips the race detector on cachedToken
// and expiresAt.
func TestAuthTokenConcurrentAccess(t *testing.T) {
	config := &Config{
		DriverName: PostgresDriverName,
		ConnString: postgresConnString,
	}
	token := &authToken{}
	builder := &fakeTokenBuilder{authToken: "the-token", expiresOn: time.Now().Add(time.Hour)}

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			got, err := token.getAuthToken(context.Background(), config, builder)
			assert.NoError(t, err)
			assert.Equal(t, "the-token", got)
		}()
	}
	wg.Wait()
}

func TestFormatDSN(t *testing.T) {
	config := &Config{
		AuthType:                  AuthTypeClientCertificate,
		TenantID:                  "tenant-id",
		ClientID:                  "client-id",
		ClientSecret:              "client-secret",
		ClientCertificatePath:     "cert-path",
		ClientCertificatePassword: "cert-password",
		SendCertificateChain:      true,
		FederatedTokenFile:        "token-file",
		ManagedIdentityResourceID: "resource-id",
		DriverName:                "driver-name",
		ConnString:                "connection-string",
	}

	dsn, err := config.FormatDSN()
	require.NoError(t, err)
	require.JSONEq(t, `{
		"auth_type": "client_certificate",
		"tenant_id": "tenant-id",
		"client_id": "client-id",
		"client_secret": "client-secret",
		"client_certificate_path": "cert-path",
		"client_certificate_password": "cert-password",
		"send_certificate_chain": true,
		"federated_token_file": "token-file",
		"managed_identity_resource_id": "resource-id",
		"driver_name": "driver-name",
		"conn_string": "connection-string"
	}`, dsn)
}

func TestAddPasswordToPostgresConnString(t *testing.T) {
	// Some GitHub runners may have populated the PGPASSWORD environment
	// variable. Have an empty value during the test.
	t.Setenv("PGPASSWORD", "")

	t.Run("password already present is rejected", func(t *testing.T) {
		_, err := addPasswordToPostgresConnString("password=already-set", "new-password")
		require.EqualError(t, err, "unexpected password in connection string for Microsoft Entra ID authentication")
	})

	t.Run("invalid connection string is rejected", func(t *testing.T) {
		_, err := addPasswordToPostgresConnString("not-valid!", "the-password")
		require.ErrorContains(t, err, "could not parse connection string")
	})

	testCases := []struct {
		name     string
		password string
	}{
		{name: "plain token", password: "plain-token-value"},
		{name: "password with a single quote", password: "token'with'quotes"},
		{name: "password with a backslash", password: `token\with\backslashes`},
		{name: "password with both", password: `it\'s got both`},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			connStringWithPassword, err := addPasswordToPostgresConnString(postgresConnString, tc.password)
			require.NoError(t, err)

			// Confirm the escaped password round-trips correctly when
			// parsed back by the postgres driver, rather than just checking
			// the raw escaped string form.
			parsed, err := pgx.ParseConfig(connStringWithPassword)
			require.NoError(t, err)
			require.Equal(t, tc.password, parsed.Password)
		})
	}
}

func TestAddPasswordToMySQLConnString(t *testing.T) {
	t.Run("password already present is rejected", func(t *testing.T) {
		_, err := addPasswordToMySQLConnString("the-user:already-set@tcp(the-host:3306)/spire", "new-password")
		require.EqualError(t, err, "unexpected password in connection string for Microsoft Entra ID authentication")
	})

	t.Run("invalid connection string is rejected", func(t *testing.T) {
		_, err := addPasswordToMySQLConnString("not-valid!", "the-password")
		require.ErrorContains(t, err, "could not parse connection string")
	})

	testCases := []struct {
		name     string
		password string
	}{
		{name: "plain token", password: "plain-token-value"},
		{name: "password with special characters", password: `p@ss'w\ord&?#`},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			connStringWithPassword, err := addPasswordToMySQLConnString(mysqlConnString, tc.password)
			require.NoError(t, err)

			// Confirm the password round-trips correctly when parsed back by
			// the mysql driver, rather than just checking the raw string form.
			parsed, err := mysql.ParseDSN(connStringWithPassword)
			require.NoError(t, err)
			require.Equal(t, tc.password, parsed.Passwd)
		})
	}
}

func TestNewAzureCredential(t *testing.T) {
	t.Run("client_secret builds a credential", func(t *testing.T) {
		cred, err := newAzureCredential(&Config{
			AuthType:     AuthTypeClientSecret,
			TenantID:     "tenant-id",
			ClientID:     "client-id",
			ClientSecret: "client-secret",
		})
		require.NoError(t, err)
		require.NotNil(t, cred)
	})

	t.Run("client_certificate builds a credential", func(t *testing.T) {
		certPath := writeTestCertPEM(t)
		cred, err := newAzureCredential(&Config{
			AuthType:              AuthTypeClientCertificate,
			TenantID:              "tenant-id",
			ClientID:              "client-id",
			ClientCertificatePath: certPath,
		})
		require.NoError(t, err)
		require.NotNil(t, cred)
	})

	t.Run("client_certificate with send_certificate_chain builds a credential", func(t *testing.T) {
		certPath := writeTestCertPEM(t)
		cred, err := newAzureCredential(&Config{
			AuthType:              AuthTypeClientCertificate,
			TenantID:              "tenant-id",
			ClientID:              "client-id",
			ClientCertificatePath: certPath,
			SendCertificateChain:  true,
		})
		require.NoError(t, err)
		require.NotNil(t, cred)
	})

	t.Run("client_certificate reports a missing file", func(t *testing.T) {
		_, err := newAzureCredential(&Config{
			AuthType:              AuthTypeClientCertificate,
			TenantID:              "tenant-id",
			ClientID:              "client-id",
			ClientCertificatePath: filepath.Join(t.TempDir(), "does-not-exist.pem"),
		})
		require.ErrorContains(t, err, "could not read client_certificate_path")
	})

	t.Run("client_certificate reports a malformed file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "cert.pem")
		require.NoError(t, os.WriteFile(path, []byte("not a certificate"), 0o600))

		_, err := newAzureCredential(&Config{
			AuthType:              AuthTypeClientCertificate,
			TenantID:              "tenant-id",
			ClientID:              "client-id",
			ClientCertificatePath: path,
		})
		require.ErrorContains(t, err, "could not parse client certificate")
	})

	t.Run("workload_identity builds a credential", func(t *testing.T) {
		cred, err := newAzureCredential(&Config{
			AuthType:           AuthTypeWorkloadIdentity,
			TenantID:           "tenant-id",
			ClientID:           "client-id",
			FederatedTokenFile: "/var/run/secrets/tokens/azure-identity-token",
		})
		require.NoError(t, err)
		require.NotNil(t, cred)
	})

	t.Run("system_managed_identity builds a credential", func(t *testing.T) {
		cred, err := newAzureCredential(&Config{
			AuthType: AuthTypeSystemManagedIdentity,
		})
		require.NoError(t, err)
		require.NotNil(t, cred)
	})

	t.Run("user_managed_identity by client ID builds a credential", func(t *testing.T) {
		cred, err := newAzureCredential(&Config{
			AuthType: AuthTypeUserManagedIdentity,
			ClientID: "client-id",
		})
		require.NoError(t, err)
		require.NotNil(t, cred)
	})

	t.Run("user_managed_identity by resource ID builds a credential", func(t *testing.T) {
		cred, err := newAzureCredential(&Config{
			AuthType:                  AuthTypeUserManagedIdentity,
			ManagedIdentityResourceID: "resource-id",
		})
		require.NoError(t, err)
		require.NotNil(t, cred)
	})

	t.Run("user_managed_identity without an ID is rejected", func(t *testing.T) {
		_, err := newAzureCredential(&Config{
			AuthType: AuthTypeUserManagedIdentity,
		})
		require.EqualError(t, err, `managed_identity_resource_id or client_id must be set for auth_type "user_managed_identity"`)
	})

	t.Run("unknown auth_type is rejected", func(t *testing.T) {
		_, err := newAzureCredential(&Config{AuthType: "bogus"})
		require.EqualError(t, err, `unsupported auth_type "bogus"`)
	})
}

// writeTestCertPEM writes a minimal self-signed certificate and private key,
// PEM-encoded, to a temp file and returns its path.
func writeTestCertPEM(t *testing.T) string {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "azurerds-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	var pemData []byte
	pemData = append(pemData, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})...)
	pemData = append(pemData, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...)

	path := filepath.Join(t.TempDir(), "cert.pem")
	require.NoError(t, os.WriteFile(path, pemData, 0o600))
	return path
}

type fakeTokenBuilder struct {
	authToken string
	expiresOn time.Time
	err       error
}

func (a *fakeTokenBuilder) buildAuthToken(context.Context, *Config) (azcore.AccessToken, error) {
	if a.err != nil {
		return azcore.AccessToken{}, a.err
	}
	return azcore.AccessToken{Token: a.authToken, ExpiresOn: a.expiresOn}, nil
}

type fakeSQLDriver struct {
	err error
}

func (d *fakeSQLDriver) Open(string) (driver.Conn, error) {
	return nil, d.err
}
