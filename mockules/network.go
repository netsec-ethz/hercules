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
	"github.com/scionproto/scion/pkg/sock/reliable"
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

func newDispatcher(daemonConn daemon.Connector) (*snet.DefaultPacketDispatcherService, error) {
	path, ok := os.LookupEnv("SCION_DISPATCHER_SOCKET")
	if !ok {
		path = reliable.DefaultDispPath
	}
	fi, err := os.Stat(path)
	if err != nil || (fi.Mode()&os.ModeSocket != os.ModeSocket) {
		return nil, fmt.Errorf("error looking for SCION dispatcher socket at %s (override with SCION_DISPATCHER_SOCKET): %w", path, err)
	}
	return &snet.DefaultPacketDispatcherService{
		Dispatcher: reliable.NewDispatcher(path),
		SCMPHandler: snet.DefaultSCMPHandler{
			RevocationHandler: daemon.RevHandler{Connector: daemonConn},
		},
	}, nil
}

func newNetwork() snet.Network {
	ctx := context.Background()
	daemonConn, err := newDaemonConn(ctx)
	if err != nil {
		exit(err)
	}
	localIA, err := daemonConn.LocalIA(ctx)
	if err != nil {
		exit(err)
	}
	dispatcher, err := newDispatcher(daemonConn)
	if err != nil {
		exit(err)
	}
	return &snet.SCIONNetwork{
		LocalIA:    localIA,
		Dispatcher: dispatcher,
	}
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
