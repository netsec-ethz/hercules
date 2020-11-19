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
	"fmt"
	log "github.com/inconshreveable/log15"
	"github.com/scionproto/scion/go/lib/pathmgr"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath/spathmeta"
	"github.com/scionproto/scion/go/lib/topology"
	"go.uber.org/atomic"
	"net"
	"time"
)

type PathsToDestination struct {
	pm             *PathManager
	dst            *Destination
	sp             *pathmgr.SyncPaths
	modifyTime     time.Time
	ExtnUpdated    atomic.Bool
	paths          []PathMeta // nil indicates that the destination is in the same AS as the sender and we can use an empty path
	canSendLocally bool       // (only if destination in same AS) indicates if we can send packets
}

type PathMeta struct {
	path        snet.Path
	fingerprint snet.PathFingerprint
	enabled     bool // Indicates whether this path can be used at the moment
	updated     bool // Indicates whether this path needs to be synced to the C path
}

type HerculesPathHeader struct {
	Header          []byte //!< C.HERCULES_MAX_HEADERLEN bytes
	PartialChecksum uint16 //SCION L4 checksum over header with 0 payload
}

func initNewPathsToDestinationWithEmptyPath(pm *PathManager, dst *Destination) *PathsToDestination {
	return &PathsToDestination{
		pm:  pm,
		dst: dst,
		sp:  nil,
		paths: nil,
		modifyTime: time.Now(),
	}
}

func initNewPathsToDestination(pm *PathManager, src *snet.UDPAddr, dst *Destination) (*PathsToDestination, error) {
	// monitor path changes
	sp, err := pm.pathResolver.Watch(context.Background(), src.IA, dst.hostAddr.IA)
	if err != nil {
		return nil, err
	}
	return &PathsToDestination{
		pm:         pm,
		dst:        dst,
		sp:         sp,
		paths:      make([]PathMeta, dst.numPaths),
		modifyTime: time.Unix(0, 0),
	}, nil
}

func (pwd *PathsToDestination) hasUsablePaths() bool {
	if pwd.paths == nil {
		return pwd.canSendLocally
	}
	for _, path := range pwd.paths {
		if path.enabled {
			return true
		}
	}
	return false
}

func (pwd *PathsToDestination) choosePaths() bool {
	if pwd.sp == nil {
		return false
	}

	pathData := pwd.sp.Load()
	if pwd.modifyTime.After(pathData.ModifyTime) {
		if pwd.ExtnUpdated.Swap(false) {
			pwd.modifyTime = time.Now()
			return true
		}
		return false
	}

	availablePaths := pathData.APS
	if len(availablePaths) == 0 {
		log.Error(fmt.Sprintf("no paths to destination %s", pwd.dst.hostAddr.IA.String()))
	}

	previousPathAvailable := make([]bool, pwd.dst.numPaths)
	updated := pwd.choosePreviousPaths(&previousPathAvailable, &availablePaths)

	if pwd.disableVanishedPaths(&previousPathAvailable) {
		updated = true
	}
	// Note: we keep vanished paths around until they can be replaced or re-enabled

	if pwd.chooseNewPaths(&previousPathAvailable, &availablePaths) {
		updated = true
	}

	if pwd.ExtnUpdated.Swap(false) || updated {
		pwd.modifyTime = time.Now()
		return true
	}
	return false
}

func (pwd *PathsToDestination) choosePreviousPaths(previousPathAvailable *[]bool, availablePaths *spathmeta.AppPathSet) bool {
	updated := false
	for _, newPath := range *availablePaths {
		newFingerprint := newPath.Fingerprint()
		for i := range pwd.paths {
			pathMeta := &pwd.paths[i]
			if newFingerprint == pathMeta.fingerprint {
				if !pathMeta.enabled {
					log.Info(fmt.Sprintf("[Destination %s] re-enabling path %d\n", pwd.dst.hostAddr.IA, i))
					pathMeta.enabled = true
					updated = true
				}
				(*previousPathAvailable)[i] = true
				break
			}
		}
	}
	return updated
}

func (pwd *PathsToDestination) disableVanishedPaths(previousPathAvailable *[]bool) bool {
	updated := false
	for i, inUse := range *previousPathAvailable {
		pathMeta := &pwd.paths[i]
		if inUse == false && pathMeta.enabled {
			log.Info(fmt.Sprintf("[Destination %s] disabling path %d\n", pwd.dst.hostAddr.IA, i))
			pathMeta.enabled = false
			updated = true
		}
	}
	return updated
}

func (pwd *PathsToDestination) chooseNewPaths(previousPathAvailable *[]bool, availablePaths *spathmeta.AppPathSet) bool {
	updated := false
	// XXX for now, we do not support replacing vanished paths
	// check that no previous path available
	for _, prev := range *previousPathAvailable {
		if prev {
			return false
		}
	}

	// pick paths
	picker := makePathPicker(pwd.dst.pathSpec, availablePaths, pwd.dst.numPaths)
	var pathSet []snet.Path
	disjointness := 0 // negative number denoting how many network interfaces are shared among paths (to be maximized)
	maxRuleIdx := 0   // the highest index of a PathSpec that is used (to be minimized)
	for i := pwd.dst.numPaths; i > 0; i-- {
		picker.reset(i)
		for picker.nextRuleSet() { // iterate through different choices of PathSpecs to use
			if pathSet != nil && maxRuleIdx < picker.maxRuleIdx() { // ignore rule set, if path set with lower maxRuleIndex is known
				continue // due to the iteration order, we cannot break here
			}
			for picker.nextPick() { // iterate through different choices of paths obeying the rules of the current set of PathSpecs
				curDisjointness := picker.disjointnessScore()
				if pathSet == nil || disjointness < curDisjointness { // maximize disjointness
					disjointness = curDisjointness
					maxRuleIdx = picker.maxRuleIdx()
					pathSet = picker.getPaths()
				}
			}
		}
		if pathSet != nil { // if no path set of size i found, try with i-1
			break
		}
	}

	log.Info(fmt.Sprintf("[Destination %s] using %d paths:", pwd.dst.hostAddr.IA, len(pathSet)))
	for i, path := range pathSet {
		log.Info(fmt.Sprintf("\t%s", path))
		pwd.paths[i].path = path
		pwd.paths[i].fingerprint = path.Fingerprint()
		pwd.paths[i].enabled = true
		pwd.paths[i].updated = true
		updated = true
	}
	return updated
}

func (pwd *PathsToDestination) preparePath(p *snet.Path) (*HerculesPathHeader, error) {
	var err error
	curDst := pwd.dst.hostAddr
	if *p == nil {
		// in order to use a static empty path, we need to set the next hop on dst
		curDst.NextHop = &net.UDPAddr{
			IP:   pwd.dst.hostAddr.Host.IP,
			Port: topology.EndhostPort,
		}
	} else {
		curDst.Path = (*p).Path()
		if curDst.Path != nil {
			if err = curDst.Path.InitOffsets(); err != nil {
				return nil, err
			}
		}

		curDst.NextHop = (*p).OverlayNextHop()
	}

	path, err := prepareSCIONPacketHeader(pwd.pm.src, curDst, pwd.pm.iface)
	if err != nil {
		return nil, err
	}
	return path, nil
}
