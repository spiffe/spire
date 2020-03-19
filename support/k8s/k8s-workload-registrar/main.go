package main

import (
	"context"
	"flag"
	"fmt"
	"os"

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
	configFlag     = flag.String("config", "k8s-workload-registrar.conf", "configuration file")
	kubeconfigFlag = flag.String("kubeconfig", "", "Path to a kubeconfig file. Only required if using informer, and running out of cluster.")
)

func main() {
	flag.Parse()
	if err := run(context.Background(), *configFlag, *kubeconfigFlag); err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, configPath string, kubeconfig string) error {
	config, err := LoadConfig(configPath)
	if err != nil {
		return err
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

	if config.UseInformer {
		// Route klog output (from client-go) to logrus
		klogFlags := flag.NewFlagSet("klog", flag.ContinueOnError)
		klog.InitFlags(klogFlags)
		// This is the only way to access this setting :(
		klogFlags.Set("logtostderr", "false")
		klog.SetOutputBySeverity("INFO", log.WriterLevel(logrus.InfoLevel))
		klog.SetOutputBySeverity("WARNING", log.WriterLevel(logrus.WarnLevel))
		klog.SetOutputBySeverity("ERROR", log.WriterLevel(logrus.ErrorLevel))
		klog.SetOutputBySeverity("FATAL", log.WriterLevel(logrus.FatalLevel))

		cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return err
		}

		client, err := kubernetes.NewForConfig(cfg)
		if err != nil {
			return err
		}

		informerFactory := informers.NewSharedInformerFactory(client, config.InformerResyncInterval)

		handler := NewInformerHandler(InformerHandlerConfig{
			Log:        log,
			Controller: controller,
			Factory:    informerFactory,
		})

		return handler.Run(ctx)
	} else {
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
	}
}
