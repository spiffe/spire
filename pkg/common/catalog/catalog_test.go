package catalog_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	log_test "github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	"github.com/spiffe/spire-plugin-sdk/private/proto/test"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/catalog/testplugin"
	"github.com/spiffe/spire/pkg/common/plugin"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

var coreConfig = catalog.CoreConfig{
	TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
}

func TestBuiltInPlugin(t *testing.T) {
	testPlugin(t, "")

	t.Run("no builtin", func(t *testing.T) {
		testLoad(t, "", loadTest{
			mutateConfig: func(config *catalog.Config) {
				config.PluginConfigs[0].Name = "quz"
			},
			expectErr: `failed to load plugin "quz": no built-in plugin "quz" for type "SomePlugin"`,
		})
	})
}

func TestExternalPlugin(t *testing.T) {
	pluginPath := buildTestPlugin(t, "./testplugin/main.go")

	testPlugin(t, pluginPath)

	t.Run("without checksum", func(t *testing.T) {
		testLoad(t, pluginPath, loadTest{
			mutateConfig: func(config *catalog.Config) {
				config.PluginConfigs[0].Checksum = ""
			},
			expectPluginClient:  true,
			expectServiceClient: true,
		})
	})

	t.Run("bad checksum", func(t *testing.T) {
		testLoad(t, pluginPath, loadTest{
			mutateConfig: func(config *catalog.Config) {
				config.PluginConfigs[0].Checksum = "NOT_A_CHECKSUM"
			},
			expectErr: `failed to load plugin "test": checksum is not a valid hex string`,
		})
		testLoad(t, pluginPath, loadTest{
			mutateConfig: func(config *catalog.Config) {
				config.PluginConfigs[0].Checksum = "DEADBEEF"
			},
			expectErr: `failed to load plugin "test": expected checksum of length 64; got 8`,
		})
		testLoad(t, pluginPath, loadTest{
			mutateConfig: func(config *catalog.Config) {
				config.PluginConfigs[0].Checksum = strings.Repeat("0", 64)
			},
			expectErr: `failed to load plugin "test": failed to launch plugin: checksums did not match`,
		})
	})

	t.Run("not a plugin", func(t *testing.T) {
		testLoad(t, pluginPath, loadTest{
			pluginMode: "bad",
			expectErr: `failed to load plugin "test": failed to launch plugin: Unrecognized remote plugin message: 
This usually means
  the plugin was not compiled for this architecture,
  the plugin is missing dynamic-link libraries necessary to run,
  the plugin is not executable by this process due to file permissions, or
  the plugin failed to negotiate the initial go-plugin protocol handshake`,
		})
	})
}

type loadTest struct {
	pluginMode            string
	registerConfigService bool
	mutateConfig          func(*catalog.Config)
	mutateRepo            func(*Repo)
	mutatePluginRepo      func(*PluginRepo)
	mutateServiceRepo     func(*ServiceRepo)
	expectErr             string
	expectPluginClient    bool
	expectServiceClient   bool
}

func testPlugin(t *testing.T, pluginPath string) {
	t.Run("binders", func(t *testing.T) {
		t.Run("plugin repo binder cannot be nil", func(t *testing.T) {
			testLoad(t, pluginPath, loadTest{
				mutatePluginRepo: func(pluginRepo *PluginRepo) {
					pluginRepo.binder = nil
				},
				expectErr: "*catalog_test.PluginRepo has an invalid binder: binder cannot be nil",
			})
		})
		t.Run("plugin repo binder is not a function", func(t *testing.T) {
			testLoad(t, pluginPath, loadTest{
				mutatePluginRepo: func(pluginRepo *PluginRepo) {
					pluginRepo.binder = 3
				},
				expectErr: "*catalog_test.PluginRepo has an invalid binder: binder is not a function",
			})
		})
		t.Run("plugin repo binder does not accept an argument", func(t *testing.T) {
			testLoad(t, pluginPath, loadTest{
				mutatePluginRepo: func(pluginRepo *PluginRepo) {
					pluginRepo.binder = func() {}
				},
				expectErr: "*catalog_test.PluginRepo has an invalid binder: binder must accept one argument",
			})
		})
		t.Run("plugin repo binder accepts too many arguments", func(t *testing.T) {
			testLoad(t, pluginPath, loadTest{
				mutatePluginRepo: func(pluginRepo *PluginRepo) {
					pluginRepo.binder = func(a, b int) {}
				},
				expectErr: "*catalog_test.PluginRepo has an invalid binder: binder must accept one argument",
			})
		})
		t.Run("plugin repo facade is not assignable to binder argument", func(t *testing.T) {
			testLoad(t, pluginPath, loadTest{
				mutatePluginRepo: func(pluginRepo *PluginRepo) {
					pluginRepo.versions[0] = badVersion{}
				},
				expectErr: "*catalog_test.PluginRepo has an invalid binder: facade catalog_test.badFacade is not assignable to argument catalog_test.SomePlugin",
			})
		})
		t.Run("service repo binder cannot be nil", func(t *testing.T) {
			testLoad(t, pluginPath, loadTest{
				mutateServiceRepo: func(serviceRepo *ServiceRepo) {
					serviceRepo.binder = nil
				},
				expectErr: "*catalog_test.ServiceRepo has an invalid binder: binder cannot be nil",
			})
		})
		t.Run("service repo binder is not a function", func(t *testing.T) {
			testLoad(t, pluginPath, loadTest{
				mutateServiceRepo: func(serviceRepo *ServiceRepo) {
					serviceRepo.binder = 3
				},
				expectErr: "*catalog_test.ServiceRepo has an invalid binder: binder is not a function",
			})
		})
		t.Run("service repo binder does not accept an argument", func(t *testing.T) {
			testLoad(t, pluginPath, loadTest{
				mutateServiceRepo: func(serviceRepo *ServiceRepo) {
					serviceRepo.binder = func() {}
				},
				expectErr: "*catalog_test.ServiceRepo has an invalid binder: binder must accept one argument",
			})
		})
		t.Run("service repo binder accepts too many arguments", func(t *testing.T) {
			testLoad(t, pluginPath, loadTest{
				mutateServiceRepo: func(serviceRepo *ServiceRepo) {
					serviceRepo.binder = func(a, b int) {}
				},
				expectErr: "*catalog_test.ServiceRepo has an invalid binder: binder must accept one argument",
			})
		})
		t.Run("service repo facade is not assignable to binder argument", func(t *testing.T) {
			testLoad(t, pluginPath, loadTest{
				mutateServiceRepo: func(serviceRepo *ServiceRepo) {
					serviceRepo.versions[0] = badVersion{}
				},
				expectErr: "*catalog_test.ServiceRepo has an invalid binder: facade catalog_test.badFacade is not assignable to argument catalog_test.SomeService",
			})
		})
	})
	t.Run("load successful", func(t *testing.T) {
		testLoad(t, pluginPath, loadTest{
			expectPluginClient:  true,
			expectServiceClient: true,
		})
	})
	t.Run("unknown type", func(t *testing.T) {
		testLoad(t, pluginPath, loadTest{
			mutateConfig: func(config *catalog.Config) {
				config.PluginConfigs[0].Type = "Quz"
			},
			expectErr: `unsupported plugin type "Quz"`,
		})
	})
	t.Run("plugin disabled", func(t *testing.T) {
		testLoad(t, pluginPath, loadTest{
			mutateConfig: func(config *catalog.Config) {
				config.PluginConfigs[0].Disabled = true
			},
			mutatePluginRepo: func(pluginRepo *PluginRepo) {
				pluginRepo.constraints = catalog.Constraints{}
			},
		})
	})
	t.Run("configure success", func(t *testing.T) {
		testLoad(t, pluginPath, loadTest{
			registerConfigService: true,
			mutateConfig: func(config *catalog.Config) {
				config.PluginConfigs[0].Data = "GOOD"
			},
			expectPluginClient:  true,
			expectServiceClient: true,
		})
	})
	t.Run("configure failure", func(t *testing.T) {
		testLoad(t, pluginPath, loadTest{
			registerConfigService: true,
			mutateConfig: func(config *catalog.Config) {
				config.PluginConfigs[0].Data = "BAD"
			},
			expectErr: `failed to configure plugin "test": rpc error: code = InvalidArgument desc = bad config`,
		})
	})
	t.Run("configure interface not registered but data supplied", func(t *testing.T) {
		testLoad(t, pluginPath, loadTest{
			mutateConfig: func(config *catalog.Config) {
				config.PluginConfigs[0].Data = "GOOD"
			},
			expectErr: `failed to configure plugin "test": no supported configuration interface found`,
		})
	})
	t.Run("constraints", func(t *testing.T) {
		t.Run("does not meet minimum", func(t *testing.T) {
			testLoad(t, pluginPath, loadTest{
				mutatePluginRepo: func(pluginRepo *PluginRepo) {
					pluginRepo.constraints = catalog.Constraints{Min: 2}
				},
				expectErr: `plugin type "SomePlugin" constraint not satisfied: expected at least 2 but got 1`,
			})
		})
		t.Run("does not meet exact", func(t *testing.T) {
			testLoad(t, pluginPath, loadTest{
				mutatePluginRepo: func(pluginRepo *PluginRepo) {
					pluginRepo.constraints = catalog.Constraints{Min: 2, Max: 2}
				},
				expectErr: `plugin type "SomePlugin" constraint not satisfied: expected exactly 2 but got 1`,
			})
		})
		t.Run("exceeds maximum", func(t *testing.T) {
			testLoad(t, pluginPath, loadTest{
				mutateConfig: func(config *catalog.Config) {
					config.PluginConfigs = append(config.PluginConfigs, config.PluginConfigs[0])
				},
				mutatePluginRepo: func(pluginRepo *PluginRepo) {
					pluginRepo.constraints = catalog.Constraints{Max: 1}
				},
				expectErr: `plugin type "SomePlugin" constraint not satisfied: expected at most 1 but got 2`,
			})
		})
		t.Run("no minimum", func(t *testing.T) {
			testLoad(t, pluginPath, loadTest{
				mutateConfig: func(config *catalog.Config) {
					config.PluginConfigs = nil
				},
				mutatePluginRepo: func(pluginRepo *PluginRepo) {
					pluginRepo.constraints = catalog.Constraints{Min: 0, Max: 1}
				},
			})
		})
		t.Run("no maximum", func(t *testing.T) {
			testLoad(t, pluginPath, loadTest{
				mutateConfig: func(config *catalog.Config) {
					for i := 0; i < 10; i++ {
						config.PluginConfigs = append(config.PluginConfigs, config.PluginConfigs[0])
					}
				},
				mutatePluginRepo: func(pluginRepo *PluginRepo) {
					pluginRepo.constraints = catalog.Constraints{Min: 1, Max: 0}
				},
				expectPluginClient:  true,
				expectServiceClient: true,
			})
		})
	})
}

func testLoad(t *testing.T, pluginPath string, tt loadTest) {
	log, hook := log_test.NewNullLogger()
	config := catalog.Config{
		Log:        log,
		CoreConfig: coreConfig,
		PluginConfigs: []catalog.PluginConfig{
			{Name: "test", Type: "SomePlugin", Path: pluginPath},
		},
		HostServices: []pluginsdk.ServiceServer{
			test.SomeHostServiceServiceServer(testplugin.SomeHostService{}),
		},
	}

	var builtIns []catalog.BuiltIn
	if pluginPath == "" {
		builtIns = append(builtIns, testplugin.BuiltIn(tt.registerConfigService))
	} else {
		config.PluginConfigs[0].Checksum = calculateChecksum(t, pluginPath)
		if tt.registerConfigService {
			config.PluginConfigs[0].Args = append(config.PluginConfigs[0].Args, "--registerConfig=true")
		}
		if tt.pluginMode != "" {
			config.PluginConfigs[0].Args = append(config.PluginConfigs[0].Args, "--mode", tt.pluginMode)
		}
	}

	var somePlugin SomePlugin
	pluginRepo := &PluginRepo{
		binder:      func(f SomePlugin) { somePlugin = f },
		clear:       func() { somePlugin = nil },
		versions:    []catalog.Version{SomePluginVersion{}},
		constraints: catalog.Constraints{Min: 1, Max: 1},
		builtIns:    builtIns,
	}

	var someService SomeService
	serviceRepo := &ServiceRepo{
		binder:   func(b SomeService) { someService = b },
		versions: []catalog.Version{SomeServiceVersion{}},
		clear:    func() { someService = nil },
	}

	repo := &Repo{
		plugins:  map[string]catalog.PluginRepo{"SomePlugin": pluginRepo},
		services: []catalog.ServiceRepo{serviceRepo},
	}

	if tt.mutateConfig != nil {
		tt.mutateConfig(&config)
	}
	if tt.mutateRepo != nil {
		tt.mutateRepo(repo)
	}
	if tt.mutatePluginRepo != nil {
		tt.mutatePluginRepo(pluginRepo)
	}
	if tt.mutateServiceRepo != nil {
		tt.mutateServiceRepo(serviceRepo)
	}

	closer, err := catalog.Load(context.Background(), config, repo)
	if closer != nil {
		defer func() {
			closer.Close()
			if tt.expectPluginClient {
				// Assert that the plugin io.Closer was invoked by looking at
				// the logs. It's hard to use the full log entry since there
				// is a bunch of unrelated, per-test-run type stuff in there,
				// so just inspect the log messages.
				assertContainsLogMessage(t, hook.AllEntries(), "CLOSED")
			}
		}()
	}

	if tt.expectErr != "" {
		require.ErrorContains(t, err, tt.expectErr, "load should have failed")
		assert.Nil(t, closer, "closer should have been nil")
	} else {
		require.NoError(t, err, "load should not have failed")
		assert.NotNil(t, closer, "closer should not have been nil")
	}

	if tt.expectPluginClient {
		if assert.NotNil(t, somePlugin, "plugin client should have been initialized") {
			assert.Equal(t, "test", somePlugin.Name())
			assert.Equal(t, "SomePlugin", somePlugin.Type())
			out, err := somePlugin.PluginEcho(context.Background(), "howdy")
			if assert.NoError(t, err, "call to PluginEcho should have succeeded") {
				// Assert that the echo response has:
				// - initial message wrapped by the plugin, then
				// - wrapped by the name of the plugin as obtained from the host service context, then
				// - wrapped by the host service
				assert.Equal(t, "hostService(test(plugin(howdy)))", out)
			}
		}
	} else {
		assert.Nil(t, somePlugin, "plugin client should not have been initialized")
	}

	if tt.expectServiceClient {
		if assert.NotNil(t, someService, "service client should have been initialized") {
			assert.Equal(t, "test", someService.Name())
			assert.Equal(t, "SomePlugin", someService.Type())
			out, err := someService.ServiceEcho(context.Background(), "howdy")
			if assert.NoError(t, err, "call to ServiceEcho should have succeeded") {
				// Assert that the echo response has:
				// - initial message wrapped by the service, then
				// - wrapped by the name of the plugin as obtained from the host service context, then
				// - wrapped by the host service
				assert.Equal(t, "hostService(test(service(howdy)))", out)
			}
		}
	} else {
		assert.Nil(t, someService, "service client should not have been initialized")
	}
}

func buildTestPlugin(t *testing.T, srcPath string) string {
	dir := spiretest.TempDir(t)

	binaryName := "test"
	if runtime.GOOS == "windows" {
		binaryName = "test.exe"
	}
	pluginPath := filepath.Join(dir, binaryName)

	now := time.Now()
	buildOutput, err := exec.Command("go", "build", "-o", pluginPath, srcPath).CombinedOutput()
	if err != nil {
		t.Logf("build output:\n%s\n", string(buildOutput))
		t.Fatal("failed to build test plugin")
	}
	t.Logf("Elapsed time to build plugin: %s", time.Since(now).Truncate(time.Millisecond))

	return pluginPath
}

func calculateChecksum(t *testing.T, path string) string {
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()

	h := sha256.New()
	_, err = io.Copy(h, f)
	require.NoError(t, err)
	return hex.EncodeToString(h.Sum(nil))
}

type Repo struct {
	plugins  map[string]catalog.PluginRepo
	services []catalog.ServiceRepo
}

func (r *Repo) Plugins() map[string]catalog.PluginRepo {
	return r.plugins
}

func (r *Repo) Services() []catalog.ServiceRepo {
	return r.services
}

type PluginRepo struct {
	binder      interface{}
	versions    []catalog.Version
	clear       func()
	constraints catalog.Constraints
	builtIns    []catalog.BuiltIn
}

func (r *PluginRepo) Binder() interface{} {
	return r.binder
}

func (r *PluginRepo) Versions() []catalog.Version {
	return r.versions
}

func (r *PluginRepo) Clear() {
	r.clear()
}

func (r *PluginRepo) Constraints() catalog.Constraints {
	return r.constraints
}

func (r *PluginRepo) BuiltIns() []catalog.BuiltIn {
	return r.builtIns
}

type ServiceRepo struct {
	binder   interface{}
	versions []catalog.Version
	clear    func()
}

func (r *ServiceRepo) Binder() interface{} {
	return r.binder
}

func (r *ServiceRepo) Versions() []catalog.Version {
	return r.versions
}

func (r *ServiceRepo) Clear() {
	r.clear()
}

type SomePlugin interface {
	catalog.PluginInfo
	PluginEcho(ctx context.Context, in string) (string, error)
}

type SomePluginFacade struct {
	plugin.Facade
	test.SomePluginPluginClient
}

func (f *SomePluginFacade) PluginEcho(_ context.Context, in string) (string, error) {
	resp, err := f.SomePluginPluginClient.PluginEcho(context.Background(), &test.EchoRequest{In: in})
	if err != nil {
		return "", err
	}
	return resp.Out, nil
}

type SomePluginVersion struct {
	deprecated bool
}

func (v SomePluginVersion) New() catalog.Facade { return new(SomePluginFacade) }

func (v SomePluginVersion) Deprecated() bool { return v.deprecated }

type SomeService interface {
	catalog.PluginInfo
	ServiceEcho(ctx context.Context, in string) (string, error)
}

type SomeServiceFacade struct {
	test.SomeServiceServiceClient
	plugin.Facade
}

func (f *SomeServiceFacade) ServiceEcho(_ context.Context, in string) (string, error) {
	resp, err := f.SomeServiceServiceClient.ServiceEcho(context.Background(), &test.EchoRequest{In: in})
	if err != nil {
		return "", err
	}
	return resp.Out, nil
}

type SomeServiceVersion struct {
	deprecated bool
}

func (v SomeServiceVersion) New() catalog.Facade { return new(SomeServiceFacade) }

func (v SomeServiceVersion) Deprecated() bool { return v.deprecated }

type badVersion struct{}

func (v badVersion) New() catalog.Facade { return badFacade{} }

func (v badVersion) Deprecated() bool { return false }

type badFacade struct{}

func (badFacade) GRPCServiceName() string                         { return "bad" }
func (badFacade) InitClient(grpc.ClientConnInterface) interface{} { return nil }
func (badFacade) InitInfo(catalog.PluginInfo)                     {}
func (badFacade) InitLog(logrus.FieldLogger)                      {}

func assertContainsLogMessage(t *testing.T, entries []*logrus.Entry, message string) {
	messages := make([]string, 0, len(entries))
	for _, entry := range entries {
		messages = append(messages, entry.Message)
	}
	assert.Contains(t, messages, message)
}
