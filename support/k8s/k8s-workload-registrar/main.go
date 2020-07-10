package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/spiffe/spire/proto/spire/api/registration"
	"github.com/zeebo/errs"
	"google.golang.org/grpc"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog"
)

var (
	configFlag = flag.String("config", "k8s-workload-registrar.conf", "configuration file")
	modeFlag   = flag.String("mode", "admission", "set operating mode, valid values are: admission, informer (default: admission)")
)

func main() {
	flag.Parse()
	if err := run(context.Background(), *configFlag, *modeFlag); err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		os.Exit(1)
	}
}

// Generic boilerplate to set up kubernetes/client-go
func setupKube(config *Config, log *log.Logger) (*kubernetes.Clientset, error) {
	// Route klog output (from client-go) to logrus
	klogFlags := flag.NewFlagSet("klog", flag.ContinueOnError)
	klog.InitFlags(klogFlags)
	// This is the only way to access these settings :(
	if err := klogFlags.Set("logtostderr", "false"); err != nil {
		return nil, err
	}
	if err := klogFlags.Set("skip_headers", "true"); err != nil {
		return nil, err
	}
	klog.SetOutputBySeverity("INFO", log.WriterLevel(logrus.InfoLevel))
	klog.SetOutputBySeverity("WARNING", log.WriterLevel(logrus.WarnLevel))
	klog.SetOutputBySeverity("ERROR", log.WriterLevel(logrus.ErrorLevel))
	klog.SetOutputBySeverity("FATAL", log.WriterLevel(logrus.FatalLevel))

	cfg, err := clientcmd.BuildConfigFromFlags("", config.KubeConfig)
	if err != nil {
		return nil, err
	}

	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}

	return client, nil
}

func run(ctx context.Context, configPath string, modeFlag string) error {
	var config *Config
	switch modeFlag {
	case "informer", "admission":
		var err error
		config, err = LoadConfig(configPath, modeFlag)
		if err != nil {
			return err
		}
	default:
		return errs.New("invalid flag --mode=%s, must be 'informer' or 'admission'invalid mode %s", modeFlag)
	}

	log, err := log.NewLogger(log.WithLevel(config.LogLevel), log.WithFormat(config.LogFormat), log.WithOutputFile(config.LogPath))
	if err != nil {
		return err
	}
	defer log.Close()

	log.WithField("socket_path", config.ServerSocketPath).Info("Dialing server")
	serverConn, err := grpc.DialContext(ctx, "unix://"+config.ServerSocketPath, grpc.WithInsecure())
	if err != nil {
		return errs.New("failed to dial server: %v", err)
	}
	defer serverConn.Close()

	controller := NewController(ControllerConfig{
		Log:           log,
		R:             registration.NewRegistrationClient(serverConn),
		TrustDomain:   config.TrustDomain,
		Cluster:       config.Cluster,
		PodLabel:      config.PodLabel,
		PodAnnotation: config.PodAnnotation,
	})

	log.Info("Initializing registrar")
	if err := controller.Initialize(ctx); err != nil {
		return err
	}

	switch modeFlag {
	case "informer":
		client, err := setupKube(config, log)
		if err != nil {
			return err
		}

		resyncInterval, err := time.ParseDuration(config.InformerResyncInterval)
		if err != nil {
			return err
		}
		informerFactory := informers.NewSharedInformerFactory(client, resyncInterval)

		handler := NewInformerHandler(InformerHandlerConfig{
			Log:        log,
			Controller: controller,
			Factory:    informerFactory,
		})

		return handler.Run(ctx)
	case "admission":
		server, err := NewServer(ServerConfig{
			Log:                            log,
			Addr:                           config.Addr,
			Handler:                        NewWebhookHandler(controller),
			CertPath:                       config.CertPath,
			KeyPath:                        config.KeyPath,
			CaCertPath:                     config.CaCertPath,
			InsecureSkipClientVerification: config.InsecureSkipClientVerification,
		})
		if err != nil {
			return err
		}
		return server.Run(ctx)
	default:
		// We handled this error at the top of the function
		panic("not reached")
	}
}
