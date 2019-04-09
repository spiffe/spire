package catalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/common/catalog/test"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type testCatalog struct {
	TestPlugin  test.TestPlugin
	TestService *test.TestService
}

type testLogEntry struct {
	Level   logrus.Level
	Message string
	Data    logrus.Fields
}

func TestCatalog(t *testing.T) {
	suite.Run(t, new(CatalogSuite))
}

type CatalogSuite struct {
	suite.Suite

	// temporary directory used to build the external plugin
	dir string

	// path to the external plugin
	path string

	// checksum of the external plugin
	checksum string

	// logging test hooks
	log     logrus.FieldLogger
	logHook *logtest.Hook

	// config
	pluginConfig  []PluginConfig
	knownPlugins  []PluginClient
	knownServices []ServiceClient
	builtins      []Plugin
	hostServices  []HostServiceServer
}

// SetupSuite builds the test plugin binary
func (s *CatalogSuite) SetupSuite() {
	require := s.Require()

	// tear down the suite if setup fails
	ok := false
	defer func() {
		if !ok {
			s.TearDownSuite()
		}
	}()

	var err error
	s.dir, err = ioutil.TempDir("", "catalog-test-")
	require.NoError(err)

	s.path = filepath.Join(s.dir, "pluginbin")
	buildOutput, err := exec.Command("go", "build", "-o", s.path, "catalog_test_plugin.go").CombinedOutput()
	if err != nil {
		s.T().Logf("build output:\n%s\n", string(buildOutput))
		s.FailNow("failed to build test plugin")
	}

	// calculate the checksum used in loading
	s.checksum, err = calculateChecksum(s.path)
	require.NoError(err, "unable to calculate plugin checksum")
	ok = true
}

func (s *CatalogSuite) TearDownSuite() {
	// clean up the temporary directory
	if s.dir != "" {
		os.RemoveAll(s.dir)
	}
}

func (s *CatalogSuite) SetupTest() {
	// reset the logger and configuration for each test
	s.log, s.logHook = logtest.NewNullLogger()
	s.knownPlugins = []PluginClient{
		test.TestPluginPluginClient,
	}
	s.knownServices = []ServiceClient{
		test.TestServiceServiceClient,
	}
	s.hostServices = []HostServiceServer{
		test.TestHostServiceHostServiceServer(test.NewTestHostService()),
	}
	s.builtins = nil
	s.pluginConfig = nil
}

func (s *CatalogSuite) AfterTest(suiteName, testName string) {
	if !s.T().Failed() {
		return
	}
	s.T().Logf("Dumping logs for failed test %s/%s:", suiteName, testName)
	for _, entry := range s.logHook.AllEntries() {
		s.T().Logf("[%s] %s %v", entry.Level, entry.Message, entry.Data)
	}
}

func (s *CatalogSuite) TestOldPlugin() {
	require := s.Require()

	path := filepath.Join(s.dir, "oldpluginbin")
	buildOutput, err := exec.Command("go", "build", "-o", path, "catalog_test_oldplugin.go").CombinedOutput()
	if err != nil {
		s.T().Logf("build output:\n%s\n", string(buildOutput))
		s.FailNow("failed to build old test plugin")
	}
	checksum, err := calculateChecksum(path)
	require.NoError(err, "unable to calculate old plugin checksum")

	plugin, err := LoadExternalPlugin(context.Background(), ExternalPlugin{
		Log:      s.log,
		Name:     "oldpluginbin",
		Path:     path,
		Checksum: checksum,
		Plugin:   test.TestPluginPluginClient,
	})
	require.NoError(err, "unable to load old plugin")
	defer plugin.Close()

	var v test.TestPlugin
	err = plugin.Fill(&v)
	require.NoError(err, "unable to get old plugin client")

	resp, err := v.CallPlugin(context.Background(), &test.Request{
		In: "OLD",
	})
	require.NoError(err, "unable to call old plugin")
	s.Require().Equal("plugin(OLD)", resp.Out)
}

func (s *CatalogSuite) TestNoKnownPlugin() {
	s.knownPlugins = nil
	s.pluginConfig = s.extPluginConfig()

	s.assertFillCatalogFails(`unknown plugin type "TestPlugin"`)
}

func (s *CatalogSuite) TestNoKnownService() {
	s.knownServices = nil

	// plugins are still loaded even if they offer unknown services
	s.assertExternalPluginCalls(
		"plugin(hostservice[plugin=testext](hello-to-plugin))",
		"",
	)

	// assert we logged a message about the unknown service
	s.assertHasLogEntry(testLogEntry{
		Level:   logrus.WarnLevel,
		Message: "Unknown service type.",
		Data: logrus.Fields{
			"service": "TestService",
		},
	})
}

func (s *CatalogSuite) TestHostServiceNotAvailable() {
	s.hostServices = nil

	s.assertExternalPluginCalls(
		"plugin(hello-to-plugin)",
		"service(hello-to-service)",
	)

	// assert we logged the message from the plugin and service about
	// the missing host service.
	s.assertHasLogEntries([]testLogEntry{
		{
			Level:   logrus.WarnLevel,
			Message: "Host service not available.",
			Data: logrus.Fields{
				"@module":        "pluginimpl",
				"hostservice":    "TestHostService",
				"subsystem_name": "external.testext.pluginbin",
			},
		},
		{
			Level:   logrus.WarnLevel,
			Message: "Host service not available.",
			Data: logrus.Fields{
				"@module":        "serviceimpl",
				"hostservice":    "TestHostService",
				"subsystem_name": "external.testext.pluginbin",
			},
		},
	})
}

func (s *CatalogSuite) TestHostServiceAvailable() {
	s.assertExternalPluginCalls(
		"plugin(hostservice[plugin=testext](hello-to-plugin))",
		"service(hostservice[plugin=testext](hello-to-service))",
	)

	s.assertHasLogEntries(extInitLogs("pluginimpl"))
}

func (s *CatalogSuite) TestDisabledPlugin() {
	s.pluginConfig = s.extPluginConfig()
	s.pluginConfig[0].Disabled = true

	s.assertFillCatalogFails(`unable to set catalog field "TestPlugin": requires at least 1 TestPlugin(s); got 0`)
}

func (s *CatalogSuite) TestUnknownBuiltIn() {
	s.pluginConfig = s.builtinConfig()

	s.assertFillCatalogFails(`no such TestPlugin builtin "testbuiltin"`)
}

func (s *CatalogSuite) TestConfigureFailure() {
	s.pluginConfig = s.extPluginConfig()
	s.pluginConfig[0].Data = "BAD"

	s.assertFillCatalogFails(`unable to configure plugin "testext": rpc error: code = InvalidArgument desc = BAD configuration`)
}

func (s *CatalogSuite) TestDuplicateKnownPlugins() {
	s.knownPlugins = []PluginClient{
		test.TestPluginPluginClient,
		test.TestPluginPluginClient,
	}
	s.assertFillCatalogFails(`duplicate plugin type "TestPlugin"`)
}

func (s *CatalogSuite) TestDuplicateKnownServices() {
	s.pluginConfig = s.extPluginConfig()
	s.knownServices = []ServiceClient{
		test.TestServiceServiceClient,
		test.TestServiceServiceClient,
	}
	s.assertFillCatalogFails(`duplicate service type "TestService"`)
}

func (s *CatalogSuite) TestDuplicateBuiltIns() {
	s.builtins = []Plugin{
		testBuiltIn(),
		testBuiltIn(),
	}
	s.assertFillCatalogFails(`duplicate TestPlugin builtin "testbuiltin"`)
}

func (s *CatalogSuite) TestPluginsFill() {
	// use a builtin w/o a service
	s.builtins = []Plugin{testBuiltInNoService()}
	// ask for the external and built in service
	s.pluginConfig = append(s.extPluginConfig(), s.builtinConfig()...)
	ps := s.loadCatalog()
	defer ps.Close()

	testCases := []struct {
		name string
		fn   func(*require.Assertions)
	}{
		{
			"nil",
			func(r *require.Assertions) {
				r.EqualError(ps.Fill(nil), "expected pointer to interface or struct (got <nil>)")
			},
		},
		{
			"empty struct",
			func(r *require.Assertions) {
				r.NoError(ps.Fill(&struct{}{}))
			},
		},
		{
			"unexported field",
			func(r *require.Assertions) {
				r.NoError(ps.Fill(&struct {
					plugins []test.TestPlugin
				}{}))
			},
		},
		{
			"single plugin constraint failure",
			func(r *require.Assertions) {
				r.EqualError(ps.Fill(&struct {
					Plugin test.TestPlugin
				}{}), `unable to set catalog field "Plugin": requires at most 1 TestPlugin(s); got 2`)
			},
		},
		{
			"optional plugin constraint failure",
			func(r *require.Assertions) {
				r.EqualError(ps.Fill(&struct {
					Plugin *test.TestPlugin
				}{}), `unable to set catalog field "Plugin": requires at most 1 TestPlugin(s); got 2`)
			},
		},
		{
			"slice of plugins",
			func(r *require.Assertions) {
				c := &struct {
					Plugins []test.TestPlugin
				}{}
				r.NoError(ps.Fill(c))
				r.Len(c.Plugins, 2)
				r.NotNil(c.Plugins[0])
				r.NotNil(c.Plugins[1])
			},
		},
		{
			"ignores other struct tags",
			func(r *require.Assertions) {
				c := &struct {
					Plugins []test.TestPlugin `json:"plugins"`
				}{}
				r.NoError(ps.Fill(c))
			},
		},
		{
			"bad struct tag",
			func(r *require.Assertions) {
				c := &struct {
					Plugins []test.TestPlugin `catalog:"BAD"`
				}{}
				r.EqualError(ps.Fill(c), `unable to set catalog field "Plugins": expected key=value for catalog tag value "BAD"`)
			},
		},
		{
			"invalid min struct tag",
			func(r *require.Assertions) {
				c := &struct {
					Plugins []test.TestPlugin `catalog:"min=BAD"`
				}{}
				r.EqualError(ps.Fill(c), `unable to set catalog field "Plugins": invalid catalog tag min value "BAD"`)
			},
		},
		{
			"negative min struct tag",
			func(r *require.Assertions) {
				c := &struct {
					Plugins []test.TestPlugin `catalog:"min=-1"`
				}{}
				r.EqualError(ps.Fill(c), `unable to set catalog field "Plugins": catalog tag min value must be >= 0`)
			},
		},
		{
			"invalid max struct tag",
			func(r *require.Assertions) {
				c := &struct {
					Plugins []test.TestPlugin `catalog:"max=BAD"`
				}{}
				r.EqualError(ps.Fill(c), `unable to set catalog field "Plugins": invalid catalog tag max value "BAD"`)
			},
		},
		{
			"negative max struct tag",
			func(r *require.Assertions) {
				c := &struct {
					Plugins []test.TestPlugin `catalog:"max=-1"`
				}{}
				r.EqualError(ps.Fill(c), `unable to set catalog field "Plugins": catalog tag max value must be > 0`)
			},
		},
		{
			"max struct tag lower than min",
			func(r *require.Assertions) {
				c := &struct {
					Plugins []test.TestPlugin `catalog:"min=2,max=1"`
				}{}
				r.EqualError(ps.Fill(c), `unable to set catalog field "Plugins": catalog tag max value must be >= min`)
			},
		},
		{
			"slice of plugins with min constraint met",
			func(r *require.Assertions) {
				c := &struct {
					Plugins []test.TestPlugin `catalog:"min=2"`
				}{}
				r.NoError(ps.Fill(c))
			},
		},
		{
			"slice of plugins with min constraint failure",
			func(r *require.Assertions) {
				c := &struct {
					Plugins []test.TestPlugin `catalog:"min=3"`
				}{}
				r.EqualError(ps.Fill(c), `unable to set catalog field "Plugins": requires at least 3 TestPlugin(s); got 2`)
			},
		},
		{
			"slice of plugins with max constraint met",
			func(r *require.Assertions) {
				c := &struct {
					Plugins []test.TestPlugin `catalog:"max=2"`
				}{}
				r.NoError(ps.Fill(c))
			},
		},
		{
			"slice of plugins with max constraint failure",
			func(r *require.Assertions) {
				c := &struct {
					Plugins []test.TestPlugin `catalog:"max=1"`
				}{}
				r.EqualError(ps.Fill(c), `unable to set catalog field "Plugins": requires at most 1 TestPlugin(s); got 2`)
			},
		},
		{
			"single service",
			func(r *require.Assertions) {
				c := &struct {
					Service test.TestService
				}{}
				r.NoError(ps.Fill(c))
				r.NotNil(c.Service)
			},
		},
		{
			"optional service",
			func(r *require.Assertions) {
				c := &struct {
					Service *test.TestService
				}{}
				r.NoError(ps.Fill(c))
				r.NotNil(c.Service)
				r.NotNil(*c.Service)
			},
		},
		{
			"slice of services",
			func(r *require.Assertions) {
				c := &struct {
					Services []test.TestService
				}{}
				r.NoError(ps.Fill(c))
				r.Len(c.Services, 1)
				r.NotNil(c.Services[0])
			},
		},
		{
			"map of string to plugin",
			func(r *require.Assertions) {
				c := &struct {
					Plugins map[string]test.TestPlugin
				}{}
				r.NoError(ps.Fill(c))
				r.Len(c.Plugins, 2)
				r.NotNil(c.Plugins["testbuiltin"])
				r.NotNil(c.Plugins["testext"])
			},
		},
		{
			"aggregated struct field",
			func(r *require.Assertions) {
				c := &struct {
					Things []struct {
						test.TestPlugin
						test.TestService
					}
				}{}
				r.NoError(ps.Fill(c))
				// an aggregated struct is only filled if a plugin implements
				// all interfaces inside the struct. since our "builtin"
				// doesn't implement TestService for this test, we only expect
				// a single "thing".
				r.Len(c.Things, 1)
				r.NotNil(c.Things[0])
				r.NotNil(c.Things[0].TestPlugin)
				r.NotNil(c.Things[0].TestService)
			},
		},
		{
			"single plugin interface constraint fails",
			func(r *require.Assertions) {
				var plugin test.TestPlugin
				r.EqualError(ps.Fill(&plugin),
					`requires at most 1 TestPlugin(s); got 2`)
			},
		},
		{
			"single service interface ok",
			func(r *require.Assertions) {
				var service test.TestService
				r.NoError(ps.Fill(&service))
				r.NotNil(service)
			},
		},
		{
			"embedded struct ok",
			func(r *require.Assertions) {
				type Embedded struct {
					Service test.TestService
				}

				c := &struct {
					Plugins []test.TestPlugin
					Embedded
				}{}

				r.NoError(ps.Fill(c))
				r.Len(c.Plugins, 2)
				r.NotNil(c.Service)
			},
		},
		{
			"embedded interface ok",
			func(r *require.Assertions) {
				c := &struct {
					Plugins []test.TestPlugin
					test.TestService
				}{}

				r.NoError(ps.Fill(c))
				r.Len(c.Plugins, 2)
				r.NotNil(c.TestService)
			},
		},
		{
			"embedded invalid type",
			func(r *require.Assertions) {
				type I int
				c := &struct {
					Plugins []test.TestPlugin
					I
				}{}
				r.EqualError(ps.Fill(c), `unable to set catalog field "I": unsupported embedded field type "catalog.I"`)
			},
		},
		{
			"embedded struct with invalid field type",
			func(r *require.Assertions) {
				type Embedded struct {
					Field int
				}

				c := &struct {
					Embedded
				}{}
				r.EqualError(ps.Fill(c), `unable to set catalog field "Embedded": unable to set catalog field "Field": unsupported field type "int"`)
			},
		},
		{
			"invalid type",
			func(r *require.Assertions) {
				c := new(int)
				r.EqualError(ps.Fill(c), `unsupported type "int"`)
			},
		},
		{
			"invalid field type",
			func(r *require.Assertions) {
				c := &struct {
					Field int
				}{}
				r.EqualError(ps.Fill(c), `unable to set catalog field "Field": unsupported field type "int"`)
			},
		},
		{
			"invalid field pointer type",
			func(r *require.Assertions) {
				c := &struct {
					Field *int
				}{}
				r.EqualError(ps.Fill(c), `unable to set catalog field "Field": pointers must be to an interface or struct (of interfaces)`)
			},
		},
		{
			"invalid field slice type",
			func(r *require.Assertions) {
				c := &struct {
					Field []int
				}{}
				r.EqualError(ps.Fill(c), `unable to set catalog field "Field": slices must be to an interface or struct (of interfaces)`)
			},
		},
		{
			"invalid field map key",
			func(r *require.Assertions) {
				c := &struct {
					Field map[int]test.TestPlugin
				}{}
				r.EqualError(ps.Fill(c), `unable to set catalog field "Field": map key type must be a string`)
			},
		},
		{
			"invalid field map value",
			func(r *require.Assertions) {
				c := &struct {
					Field map[string]int
				}{}
				r.EqualError(ps.Fill(c), `unable to set catalog field "Field": map value type must be to an interface or struct (of interfaces)`)
			},
		},
		{
			"can get plugin info",
			func(r *require.Assertions) {
				c := &struct {
					JustPluginInfos     []PluginInfo
					PluginInfosInStruct []struct {
						PluginInfo
						test.TestPlugin
					}
				}{}
				r.NoError(ps.Fill(c))
				// an aggregated struct is only filled if a plugin implements
				// all interfaces inside the struct. since our "builtin"
				// doesn't implement TestService for this test, we only expect
				// a single "thing".
				r.Len(c.JustPluginInfos, 2)
				r.Equal("testext", c.JustPluginInfos[0].Name())
				r.Equal("testbuiltin", c.JustPluginInfos[1].Name())
				r.Len(c.PluginInfosInStruct, 2)
				r.Equal("testext", c.PluginInfosInStruct[0].Name())
				r.Equal("testbuiltin", c.PluginInfosInStruct[1].Name())
			},
		},
	}

	for _, testCase := range testCases {
		s.T().Run(testCase.name, func(t *testing.T) {
			testCase.fn(require.New(t))
		})
	}
}

func (s *CatalogSuite) assertFillCatalogFails(expectedErr string) {
	c := new(testCatalog)
	closer, err := s.fillCatalog(c)
	if !s.EqualError(err, expectedErr) {
		closer.Close()
	}
}

func (s *CatalogSuite) assertExternalPluginCalls(pluginOut, serviceOut string) {
	s.pluginConfig = s.extPluginConfig()

	assert := s.Assert()
	require := s.Require()

	c := new(testCatalog)
	closer, err := s.fillCatalog(c)
	require.NoError(err)
	defer closer.Close()

	resp, err := c.TestPlugin.CallPlugin(context.Background(), &test.Request{
		In: "hello-to-plugin",
	})
	require.NoError(err)
	assert.Equal(pluginOut, resp.Out)

	if c.TestService != nil {
		resp, err = (*c.TestService).CallService(context.Background(), &test.Request{
			In: "hello-to-service",
		})
		require.NoError(err)
		assert.Equal(serviceOut, resp.Out)
	} else if serviceOut != "" {
		assert.Fail("service was not available")
	}
}

func (s *CatalogSuite) fillCatalog(c interface{}) (Closer, error) {
	return Fill(context.Background(), Config{
		Log: s.log,
		GlobalConfig: GlobalConfig{
			TrustDomain: "domain.test",
		},
		PluginConfig:  s.pluginConfig,
		KnownPlugins:  s.knownPlugins,
		KnownServices: s.knownServices,
		BuiltIns:      s.builtins,
		HostServices:  s.hostServices,
	}, c)
}

func (s *CatalogSuite) loadCatalog() Catalog {
	cat, err := Load(context.Background(), Config{
		Log: s.log,
		GlobalConfig: GlobalConfig{
			TrustDomain: "domain.test",
		},
		PluginConfig:  s.pluginConfig,
		KnownPlugins:  s.knownPlugins,
		KnownServices: s.knownServices,
		HostServices:  s.hostServices,
		BuiltIns:      s.builtins,
	})
	s.Require().NoError(err)
	return cat
}

func (s *CatalogSuite) extPluginConfig() []PluginConfig {
	return []PluginConfig{
		{
			Name:     "testext",
			Type:     test.TestPluginType,
			Path:     s.path,
			Checksum: s.checksum,
			Data:     "CONFIG",
		},
	}
}

func (s *CatalogSuite) builtinConfig() []PluginConfig {
	return []PluginConfig{
		{
			Name: "testbuiltin",
			Type: test.TestPluginType,
			Data: "CONFIG",
		},
	}
}

func (s *CatalogSuite) assertHasLogEntries(entries []testLogEntry) bool {
	ok := true
	for _, e := range entries {
		if !s.assertHasLogEntry(e) {
			ok = false
		}
	}
	return ok
}

func (s *CatalogSuite) assertHasLogEntry(e testLogEntry) bool {
	for _, a := range s.logHook.AllEntries() {
		if reflect.DeepEqual(testLogEntryFromEntry(a), e) {
			return true
		}
	}
	return s.Failf("no such log entry", "level=%q message=%q data=%q", e.Level, e.Message, e.Data)
}

func testLogEntryFromEntry(entry *logrus.Entry) testLogEntry {
	// drop timestamp, since it is problematic to compare
	delete(entry.Data, "timestamp")
	return testLogEntry{
		Level:   entry.Level,
		Message: entry.Message,
		Data:    entry.Data,
	}
}

func testBuiltIns() []Plugin {
	return []Plugin{
		testBuiltIn(),
	}
}

func testBuiltIn() Plugin {
	builtin := testBuiltInNoService()
	builtin.Services = append(builtin.Services, test.TestServiceServiceServer(test.NewTestService()))
	return builtin
}

func testBuiltInNoService() Plugin {
	return MakePlugin("testbuiltin",
		test.TestPluginPluginServer(test.NewTestPlugin()),
	)
}

func calculateChecksum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func extInitLogs(module string) []testLogEntry {
	return []testLogEntry{
		{
			Level:   logrus.InfoLevel,
			Message: "Configure called.",
			Data: logrus.Fields{
				"@module":        module,
				"config":         "CONFIG",
				"subsystem_name": "external.testext.pluginbin",
				"trustdomain":    "domain.test",
			},
		},
		{
			Level:   logrus.InfoLevel,
			Message: "Plugin loaded.",
			Data: logrus.Fields{
				"built-in": false,
				"name":     "testext",
				"services": []string{"TestService"},
				"type":     "TestPlugin",
			},
		},
	}
}
