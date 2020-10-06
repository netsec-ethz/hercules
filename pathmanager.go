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

import (
	"context"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/pathmgr"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/snet"
	"net"
	"time"
)

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
	syncTime           time.Time
	pathResolver       pathmgr.Resolver
	maxBps             uint64
	cStruct            CPathManagement
}

const numPathsResolved = 20

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func initNewPathManager(iface *net.Interface, dsts []*Destination, src *snet.UDPAddr, maxBps uint64) (*PathManager, error) {
	sciondConn, err := sciond.NewService(sciond.DefaultSCIONDAddress).Connect(context.Background())
	if err != nil {
		return nil, err
	}

	numPathsPerDst := 0
	pm := &PathManager{
		iface:         iface,
		src:           src,
		dsts:          make([]*PathsToDestination, 0, len(dsts)),
		syncTime:      time.Unix(0, 0),
		maxBps:        maxBps,
		pathResolver:  pathmgr.New(sciondConn, pathmgr.Timers{}, uint16(numPathsResolved)),
	}

	for _, dst := range dsts {
		var dstState *PathsToDestination
		if src.IA == dst.ia {
			dstState = initNewPathsToDestinationWithEmptyPath(pm, dst)
		} else {
			dstState, err = initNewPathsToDestination(pm, src, dst)
			if err != nil {
				return nil, err
			}
		}
		pm.dsts = append(pm.dsts, dstState)
		numPathsPerDst = max(numPathsPerDst, dst.numPaths)
	}

	// allocate memory to pass paths to C
	pm.numPathSlotsPerDst = numPathsPerDst
	pm.cStruct.initialize(len(dsts), numPathsPerDst)
	return pm, nil
}

func (pm *PathManager) canSendToAllDests() bool {
	for _, dst := range pm.dsts {
		if !dst.hasUsablePaths() {
			return false
		}
	}
	return true
}

func (pm *PathManager) choosePaths() bool {
	updated := false
	for _, dst := range pm.dsts {
		if dst.choosePaths() {
			updated = true
		}
	}
	return updated
}

func (pm *PathManager) syncPathsToC() {
	ticker := time.NewTicker(500 * time.Millisecond)
	for range ticker.C {
		if pm.choosePaths() {
			pm.pushPaths()
		}
	}
}
