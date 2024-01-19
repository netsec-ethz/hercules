// Copyright 2023 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"fmt"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/snet"
	"os"
)

func exit(err error) {
	fmt.Fprintf(os.Stderr, "Error initializing SCION network: %v\n", err)
	os.Exit(1)
}

func newDaemonConn(ctx context.Context) (daemon.Connector, error) {
	address, ok := os.LookupEnv("SCION_DAEMON_ADDRESS")
	if !ok {
		address = daemon.DefaultAPIAddress
	}
	daemonConn, err := daemon.NewService(address).Connect(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to connect to SCIOND at %s (override with SCION_DAEMON_ADDRESS): %w", address, err)
	}
	return daemonConn, nil
}

func newPathQuerier() snet.PathQuerier {
	ctx := context.Background()
	daemonConn, err := newDaemonConn(ctx)
	if err != nil {
		exit(err)
	}
	localIA, err := daemonConn.LocalIA(ctx)
	if err != nil {
		exit(err)
	}
	return daemon.Querier{
		Connector: daemonConn,
		IA:        localIA,
	}
}
