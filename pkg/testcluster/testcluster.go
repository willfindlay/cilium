package testcluster

import (
	"flag"
	"fmt"
	"os"
	"testing"

	"sigs.k8s.io/e2e-framework/pkg/env"
)

var globalConfig *config

func Environment(t *testing.T) env.Environment {
	t.Helper()
	environment, err := globalConfig.environment()
	if err != nil {
		t.Fatal(err)
	}
	return environment
}

func Main(m *testing.M) {
	var err error
	globalConfig, err = newConfig()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	globalConfig.addFlags(flag.CommandLine)
	flag.Parse()
	os.Exit(m.Run())
}
