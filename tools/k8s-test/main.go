package main

import (
	"context"
	"os"
	"time"

	"github.com/spf13/cobra"
)

func main() {
	const defaultInterval = time.Second * 2

	var count int
	var noWait bool
	var noLocal bool
	var timeout time.Duration
	var interval time.Duration

	// cancel the context
	// note: have to run an unnamed function here so we cancel the latest
	// "cancel" function (it is mutated by the root command)
	ctx := context.Background()
	cancel := func() {}
	defer func() {
		cancel()
	}()

	root := &cobra.Command{
		Use: "k8s",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if timeout > 0 {
				ctx, cancel = context.WithTimeout(ctx, timeout)
			}
		},
	}
	root.PersistentFlags().DurationVarP(&timeout, "timeout", "t", time.Minute, "how long before timing out the command")

	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Initializes the test environment",
		Long:  "Initializes the test environment",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			runCmd(InitCmd(ctx))
		},
	}
	root.AddCommand(initCmd)

	cleanCmd := &cobra.Command{
		Use:   "clean",
		Short: "Cleans the test environment",
		Long:  "Cleans the test environment",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			runCmd(CleanCmd(ctx))
		},
	}
	root.AddCommand(cleanCmd)

	waitCmd := &cobra.Command{
		Use:   "wait",
		Long:  "Wait for deployments, daemon sets, attestation events, etc.",
		Short: "Wait for deployments, daemon sets, attestation events, etc.",
	}
	root.AddCommand(waitCmd)

	waitDeploymentCmd := &cobra.Command{
		Use:   "deployment",
		Short: "Wait for a deployment to be ready",
		Long:  "Wait for a deployment to be ready",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			runCmd(WaitForDeploymentCmd(ctx, args[0], interval))
		},
	}
	waitDeploymentCmd.LocalFlags().DurationVarP(&interval, "interval", "i", defaultInterval, "polling interval for deployment status")
	waitCmd.AddCommand(waitDeploymentCmd)

	waitDaemonSetCmd := &cobra.Command{
		Use:   "daemonset",
		Short: "Wait for a daemon set to be ready",
		Long:  "Wait for a daemon set to be ready",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			runCmd(WaitForDaemonSetCmd(ctx, args[0], interval))
		},
	}
	waitDaemonSetCmd.LocalFlags().DurationVarP(&interval, "interval", "i", defaultInterval, "polling interval for daemon set status")
	waitCmd.AddCommand(waitDaemonSetCmd)

	waitNodeAttestationCmd := &cobra.Command{
		Use:   "node-attestation",
		Short: "wait for node attestation",
		Long:  "wait for node attestation",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			runCmd(WaitForNodeAttestationCmd(ctx, args[0], count))
		},
	}
	waitNodeAttestationCmd.LocalFlags().IntVarP(&count, "count", "c", 1, "number of nodes expected to attest")
	waitCmd.AddCommand(waitNodeAttestationCmd)

	applyCmd := &cobra.Command{
		Use:  "apply",
		Args: cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			runCmd(ApplyConfigCmd(ctx, args, !noWait, !noLocal, interval))
		},
	}
	applyCmd.LocalFlags().BoolVarP(&noWait, "no-wait", "", false, "don't wait for all objects after applying")
	applyCmd.LocalFlags().BoolVarP(&noLocal, "no-local", "", false, "don't use locally built SPIRE images")
	applyCmd.LocalFlags().DurationVarP(&interval, "interval", "i", defaultInterval, "polling interval for object status")
	root.AddCommand(applyCmd)

	root.Execute()
}

func InitCmd(ctx context.Context) error {
	Infoln("initializing test environment...")
	if err := DeleteNamespaceIfExist(ctx, NamespaceName); err != nil {
		return err
	}
	if err := CreateNamespace(ctx, NamespaceName); err != nil {
		return err
	}
	Infoln("initialization done.")
	return nil
}

func CleanCmd(ctx context.Context) error {
	Infoln("cleaning test environment...")
	if err := DeleteNamespaceIfExist(context.Background(), NamespaceName); err != nil {
		return err
	}
	Infoln("cleaning done.")
	return nil
}

func WaitForDeploymentCmd(ctx context.Context, name string, interval time.Duration) error {
	return WaitForDeployment(ctx, name, interval)
}

func WaitForDaemonSetCmd(ctx context.Context, name string, interval time.Duration) error {
	return WaitForDaemonSet(ctx, name, interval)
}

func WaitForNodeAttestationCmd(ctx context.Context, ident string, count int) error {
	server, err := ParseObject(ident)
	if err != nil {
		return err
	}

	return WaitForNodeAttestation(ctx, server, count)
}

func ApplyConfigCmd(ctx context.Context, paths []string, wait, local bool, interval time.Duration) error {
	var all []Object

	for _, path := range paths {
		objects, err := ApplyConfig(ctx, path, local)
		if err != nil {
			Alertln("failed to apply %s", path)
			return err
		}
		Goodln("applied %s.", path)
		all = append(all, objects...)
	}

	if wait {
		Infoln("waiting for configured objects...")
		return WaitForObjects(ctx, all, interval)
	}
	return nil
}

func runCmd(err error) {
	if err != nil {
		Alertln(err.Error())
		os.Exit(1)
	}
}
