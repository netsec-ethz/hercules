// Copyright 2019 ETH Zurich
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

// #cgo CFLAGS: -std=c11 -O3 -Wall -DNDEBUG -D_GNU_SOURCE -march=broadwell -mtune=broadwell
// #cgo LDFLAGS: ${SRCDIR}/bpf/libbpf.a -lm -lelf -pthread
// #pragma GCC diagnostic ignored "-Wunused-variable" // Hide warning in cgo-gcc-prolog
// #include "hercules.h"
// #include <linux/if_xdp.h>
// #include <stdint.h>
// #include <stdlib.h>
// #include <string.h>
import "C"
import (
	"github.com/google/gopacket"
	"github.com/scionproto/scion/go/lib/pathmgr"
	"github.com/scionproto/scion/go/lib/snet"
	"go.uber.org/atomic"
	"hercules/mock_sibra/resvmgr" // TODO replace this with real API once it becomes available
	"net"
	"time"
)

type arrayFlags []string

type HerculesPath struct {
	Header          []byte //!< C.HERCULES_MAX_HEADERLEN bytes
	PartialChecksum uint16 //SCION L4 checksum over header with 0 payload
}

type SibraHerculesPath struct {
	*HerculesPath
	ws     *resvmgr.WatchState
	MaxBps uint64
}

type herculesStats = C.struct_hercules_stats

type layerWithOpts struct {
	Layer gopacket.SerializableLayer
	Opts  gopacket.SerializeOptions
}

type PathManager struct {
	numPathsPerDst     int
	iface              *net.Interface
	dsts               []*PathsToDestination
	src                *snet.UDPAddr
	cNumPathsPerDst    []C.int
	cMaxNumPathsPerDst C.int
	cPathsPerDest      []C.struct_hercules_path
	syncTime           time.Time
	sibraMgr           *resvmgr.Mgr
	useBestEffort      bool
	maxBps             uint64
}

type PathMeta struct {
	path        snet.Path
	fingerprint snet.PathFingerprint
	enabled     bool // Indicates whether this path can be used at the moment
	updated     bool // Indicates whether this path needs to be synced to the C path

	// SIBRA related
	sbrWs      *resvmgr.WatchState
	sbrEnabled atomic.Bool // Indicates whether the SIBRA extension can be used at the moment (i.e. SIBRA resolver is running)
	sbrUpdated atomic.Bool // Indicates whether the SIBRA status needs to be synced to the C part
}

type PathsToDestination struct {
	addr        *snet.UDPAddr
	sp          *pathmgr.SyncPaths
	modifyTime  time.Time
	ExtnUpdated atomic.Bool
	paths       []PathMeta
}
