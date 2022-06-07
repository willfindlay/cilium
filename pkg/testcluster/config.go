package testcluster

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/envfuncs"
)

const (
	clusterTypeKind       = "kind"
	clusterTypeKubeConfig = "kube-config"
	clusterTypeShell      = "shell"
)

type kubeconfigProvisionerConfig struct {
	file string
}

type shellProvisionerConfig struct {
	setup  string
	finish string
}

type config struct {
	sync.Mutex
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
	flagSet.StringVar(&c.shell.setup, "shell-setup", c.shell.setup, "shell setup")
	flagSet.StringVar(&c.shell.finish, "shell-finish", c.shell.finish, "shell finish")
	flagSet.StringVar(&c.clusterNamePrefix, "cluster-name-prefix", c.clusterNamePrefix, "cluster name prefix")
	flagSet.StringVar(&c.namespaceNamePrefix, "namespace-name-prefix", c.namespaceNamePrefix, "namespace name prefix")
}

func (c *config) environment() (env.Environment, error) {
	c.Lock()
	defer c.Unlock()

	if c.currentEnvironment != nil {
		return c.currentEnvironment, nil
	}

	switch c.provisioner {
	case clusterTypeKind:
		clusterName := c.clusterNameFunc(c.clusterNamePrefix)
		namespaceName := c.namespaceNameFunc(c.namespaceNamePrefix)
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
	case clusterTypeKubeConfig:
		c.currentEnvironment = env.NewWithKubeConfig(c.kubeconfig.file)
		return c.currentEnvironment, nil
	case clusterTypeShell:
		environment := env.New()
		environment.Setup(
			runShellCommand(c.shell.setup),
		)
		environment.Finish(
			runShellCommand(c.shell.finish),
		)
		return c.currentEnvironment, nil
	default:
		return nil, fmt.Errorf("%s: unknown provisioner", c.provisioner)
	}
}

func randomNameFunc(prefix string) string {
	return envconf.RandomName(prefix, 16)
}

func runShellCommand(command string) env.Func {
	return func(ctx context.Context, config *envconf.Config) (context.Context, error) {
		if command == "" {
			return ctx, nil
		}

		shell, ok := os.LookupEnv("SHELL")
		if !ok {
			shell = "/bin/sh"
		}

		cmd := exec.CommandContext(ctx, shell, "-c", command)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return nil, err
		}

		return ctx, nil
	}
}
