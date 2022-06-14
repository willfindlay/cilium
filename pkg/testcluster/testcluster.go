package testcluster

import (
	"context"
	"flag"
	"fmt"
	"os"
	"testing"

	"sigs.k8s.io/e2e-framework/pkg/env"
)

// Env is the test environment.
var Env env.Environment

func Main(m *testing.M) {
	c, err := newConfig()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	c.addFlags(flag.CommandLine)
	flag.Parse()

	ctx := context.Background()
	Env, err = c.environment(ctx)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	os.Exit(Env.Run(m))
}
