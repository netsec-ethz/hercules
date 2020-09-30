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

// #cgo CFLAGS: -O3 -Wall -DNDEBUG -D_GNU_SOURCE -march=broadwell -mtune=broadwell
// #cgo LDFLAGS: ${SRCDIR}/bpf/libbpf.a -lm -lelf -pthread -lz
// #pragma GCC diagnostic ignored "-Wunused-variable" // Hide warning in cgo-gcc-prolog
// #include "hercules.h"
// #include <linux/if_xdp.h>
// #include <stdint.h>
// #include <stdlib.h>
// #include <string.h>
import "C"
import (
	"github.com/google/gopacket"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/pathmgr"
	"github.com/scionproto/scion/go/lib/snet"
	"go.uber.org/atomic"
	"net"
	"time"
)

type arrayFlags []string

type HerculesPathHeader struct {
	Header          []byte //!< C.HERCULES_MAX_HEADERLEN bytes
	PartialChecksum uint16 //SCION L4 checksum over header with 0 payload
}

type herculesStats = C.struct_hercules_stats

type aggregateStats struct {
	maxPps float64
	maxBpsThru float64
	maxBpsGood float64
}

type layerWithOpts struct {
	Layer gopacket.SerializableLayer
	Opts  gopacket.SerializeOptions
}

type Destination struct {
	ia        addr.IA
	hostAddrs []*net.UDPAddr
	pathSpec  *[]PathSpec
	numPaths  int
}

type PathManager struct {
	numPathSlotsPerDst int
	iface              *net.Interface
	dsts               []*PathsToDestination
	src                *snet.UDPAddr
	cNumPathsPerDst    []C.int
	cMaxNumPathsPerDst C.int
	cPathsPerDest      []C.struct_hercules_path
	syncTime           time.Time
	pathResolver       pathmgr.Resolver
	maxBps             uint64
}

type PathMeta struct {
	path        snet.Path
	fingerprint snet.PathFingerprint
	enabled     bool // Indicates whether this path can be used at the moment
	updated     bool // Indicates whether this path needs to be synced to the C path
}

type PathsToDestination struct {
	pm             *PathManager
	dst            *Destination
	sp             *pathmgr.SyncPaths
	modifyTime     time.Time
	ExtnUpdated    atomic.Bool
	paths          []PathMeta // nil indicates that the destination is in the same AS as the sender and we can use an empty path
	canSendLocally bool // (only if destination in same AS) indicates if we can send packets
}

type Flags struct {
	dumpInterval     time.Duration
	enablePCC        bool
	ifname           string
	localAddrs       arrayFlags
	maxRateLimit     int
	mode             string
	mtu              int
	queueArgs        arrayFlags
	remoteAddrs      arrayFlags
	transmitFilename string
	outputFilename   string
	verbose          string
	numPaths         int
}

type HerculesGeneralConfig struct {
	Direction    string
	DumpInterval time.Duration
	Interface    string
	Mode         string
	MTU          int
	Queues       []int
	Verbosity    string
}

type SiteConfig struct {
	IA        addr.IA
	HostAddrs []string
	NumPaths  int
	PathSpec  []PathSpec
}

type HerculesReceiverConfig struct {
	HerculesGeneralConfig
	OutputFile      string
	LocalAddresses  SiteConfig
	ConfigureQueues bool
}

type HerculesSenderConfig struct {
	HerculesGeneralConfig
	TransmitFile       string
	EnablePCC          bool
	RateLimit          int
	LocalAddress       string
	NumPathsPerDest    int
	Destinations       []SiteConfig
}

type PathInterface struct {
	ia   addr.IA
	ifId common.IFIDType
}

type PathSpec []PathInterface

type PathPickDescriptor struct {
	ruleIndex int
	pathIndex int
}

type PathPicker struct {
	pathSpec        *[]PathSpec
	availablePaths  []snet.Path
	currentPathPick []PathPickDescriptor
}
