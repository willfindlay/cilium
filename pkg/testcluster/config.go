package testcluster

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/envfuncs"
)

const (
	clusterTypeKind       = "kind"
	clusterTypeKubeconfig = "kubeconfig"
	clusterTypeShell      = "shell"
)

type kubeconfigProvisionerConfig struct {
	file string
}

type shellProvisionerConfig struct {
	setup  string
	finish string
	keep   bool
}

type config struct {
	provisioner         string
	kubeconfig          kubeconfigProvisionerConfig
	shell               shellProvisionerConfig
	clusterNamePrefix   string
	clusterNameFunc     func(string) string
	namespaceNamePrefix string
	namespaceNameFunc   func(string) string
	currentEnvironment  env.Environment
}

type configOption func(*config) error

func newConfig(options ...configOption) (*config, error) {
	userHomeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	c := &config{
		provisioner: clusterTypeKind,
		kubeconfig: kubeconfigProvisionerConfig{
			file: filepath.Join(userHomeDir, ".kube", "config"),
		},
		clusterNamePrefix:   "testcluster",
		clusterNameFunc:     randomNameFunc,
		namespaceNamePrefix: "testnamespace",
		namespaceNameFunc:   randomNameFunc,
	}

	for _, option := range options {
		if err := option(c); err != nil {
			return nil, err
		}
	}

	return c, nil
}

func (c *config) addFlags(flagSet *flag.FlagSet) {
	flagSet.StringVar(&c.provisioner, "provisioner", c.provisioner, "provisioner")
	flagSet.StringVar(&c.kubeconfig.file, "kubeconfig-file", c.kubeconfig.file, "kubeconfig file")
	flagSet.StringVar(&c.shell.setup, "shell-setup", c.shell.setup, "shell setup command")
	flagSet.StringVar(&c.shell.finish, "shell-finish", c.shell.finish, "shell finish command")
	flagSet.BoolVar(&c.shell.keep, "shell-keep", c.shell.keep, "shell keep temporary directory")
	flagSet.StringVar(&c.clusterNamePrefix, "cluster-name-prefix", c.clusterNamePrefix, "cluster name prefix")
	flagSet.StringVar(&c.namespaceNamePrefix, "namespace-name-prefix", c.namespaceNamePrefix, "namespace name prefix")
}

func (c *config) environment(ctx context.Context) (env.Environment, error) {
	if c.currentEnvironment != nil {
		return c.currentEnvironment, nil
	}

	namespaceName := c.namespaceNameFunc(c.namespaceNamePrefix)
	switch c.provisioner {
	case clusterTypeKind:
		clusterName := c.clusterNameFunc(c.clusterNamePrefix)
		environment := env.New()
		environment.Setup(
			envfuncs.CreateKindCluster(clusterName),
			envfuncs.CreateNamespace(namespaceName),
		)
		environment.Finish(
			envfuncs.DeleteNamespace(namespaceName),
			envfuncs.DestroyKindCluster(clusterName),
		)
		c.currentEnvironment = environment
		return c.currentEnvironment, nil
	case clusterTypeKubeconfig:
		environment := env.NewWithKubeConfig(c.kubeconfig.file)
		environment.Setup(
			envfuncs.CreateNamespace(namespaceName),
		)
		environment.Finish(
			envfuncs.DeleteNamespace(namespaceName),
		)
		c.currentEnvironment = environment
		return c.currentEnvironment, nil
	case clusterTypeShell:
		tempDir, err := os.MkdirTemp("", "testcluster-*")
		if err != nil {
			return nil, err
		}
		kubeconfigFile := filepath.Join(tempDir, "kubeconfig")
		if err := runShellCommand(ctx, c.shell.setup, kubeconfigFile); err != nil {
			return nil, err
		}
		environment := env.NewWithKubeConfig(kubeconfigFile)
		environment.Finish(
			runShellCommandEnvFunc(c.shell.finish),
			func(ctx context.Context, config *envconf.Config) (context.Context, error) {
				if !c.shell.keep {
					if err := os.RemoveAll(tempDir); err != nil {
						return nil, err
					}
				}
				return ctx, nil
			},
		)
		c.currentEnvironment = environment
		return c.currentEnvironment, nil
	default:
		return nil, fmt.Errorf("%s: unknown provisioner", c.provisioner)
	}
}

func randomNameFunc(prefix string) string {
	return envconf.RandomName(prefix, 16)
}

func runShellCommandEnvFunc(command string) env.Func {
	return func(ctx context.Context, config *envconf.Config) (context.Context, error) {
		if command == "" {
			return ctx, nil
		}

		if err := runShellCommand(ctx, command); err != nil {
			return nil, err
		}

		return ctx, nil
	}
}

func runShellCommand(ctx context.Context, command string, args ...string) error {
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
