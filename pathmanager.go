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
	"fmt"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/vishvananda/netlink"
	"net"
	"time"
)

type Destination struct {
	hostAddr *snet.UDPAddr
	pathSpec *[]PathSpec
	numPaths int
}

type PathManager struct {
	numPathSlotsPerDst int
	interfaces         map[int]*net.Interface
	dsts               []*PathsToDestination
	src                *snet.UDPAddr
	syncTime           time.Time
	maxBps             uint64
	cStruct            CPathManagement
}

type PathWithInterface struct {
	path  snet.Path
	iface *net.Interface
}

type AppPathSet map[snet.PathFingerprint]PathWithInterface

const numPathsResolved = 20

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func initNewPathManager(interfaces []*net.Interface, dsts []*Destination, src *snet.UDPAddr, maxBps uint64) (*PathManager, error) {
	ifMap := make(map[int]*net.Interface)
	for _, iface := range interfaces {
		ifMap[iface.Index] = iface
	}

	numPathsPerDst := 0
	pm := &PathManager{
		interfaces:   ifMap,
		src:          src,
		dsts:         make([]*PathsToDestination, 0, len(dsts)),
		syncTime:     time.Unix(0, 0),
		maxBps:       maxBps,
	}

	for _, dst := range dsts {
		var dstState *PathsToDestination
		if src.IA == dst.hostAddr.IA {
			dstState = initNewPathsToDestinationWithEmptyPath(pm, dst)
		} else {
			var err error
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

func (pm *PathManager) filterPathsByActiveInterfaces(pathsAvail []snet.Path) AppPathSet {
	pathsFiltered := make(AppPathSet)
	for _, path := range pathsAvail {
		iface, err := pm.interfaceForRoute(path.UnderlayNextHop().IP)
		if err != nil {
		} else {
			pathsFiltered[snet.Fingerprint(path)] = PathWithInterface{path, iface}
		}
	}
	return pathsFiltered
}

func (pm *PathManager) interfaceForRoute(ip net.IP) (*net.Interface, error) {
	routes, err := netlink.RouteGet(ip)
	if err != nil {
		return nil, fmt.Errorf("could not find route for destination %s: %s", ip, err)
	}

	for _, route := range routes {
		if iface, ok := pm.interfaces[route.LinkIndex]; ok {
			fmt.Printf("sending via #%d (%s) to %s\n", route.LinkIndex, pm.interfaces[route.LinkIndex].Name, ip)
			return iface, nil
		}
	}
	return nil, fmt.Errorf("no interface active for sending to %s", ip)
}
