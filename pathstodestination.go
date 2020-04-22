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
	"context"
	"fmt"
	log "github.com/inconshreveable/log15"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath/spathmeta"
	"github.com/scionproto/scion/go/lib/topology"
	"hercules/mock_sibra/lib/sibra"
	"hercules/mock_sibra/resvmgr" // TODO replace this with real API once it becomes available
	"net"
	"time"
)

func initNewPathsToDestinationWithEmptyPath(pm *PathManager, dst *snet.UDPAddr) *PathsToDestination {
	// in order to use a static empty path, we need to set the next hop on dst
	dst.NextHop = &net.UDPAddr{
		IP:   dst.Host.IP,
		Port: topology.EndhostPort,
	}

	return &PathsToDestination{
		pm:   pm,
		addr: dst,
		sp:   nil,
		paths: []PathMeta{{
			enabled: true,
		}},
		modifyTime: time.Now(),
	}
}

func initNewPathsToDestination(pm *PathManager, src, dst *snet.UDPAddr, numPaths int) (*PathsToDestination, error) {
	// monitor path changes
	sp, err := pm.pathResolver.Watch(context.Background(), src.IA, dst.IA)
	if err != nil {
		return nil, err
	}
	return &PathsToDestination{
		pm:         pm,
		addr:       dst,
		sp:         sp,
		paths:      make([]PathMeta, numPaths),
		modifyTime: time.Unix(0, 0),
	}, nil
}

func (pwd *PathsToDestination) hasUsablePaths() bool {
	for _, path := range pwd.paths {
		if path.enabled {
			return true
		}
	}
	return false
}

func (pwd *PathsToDestination) pushPaths(pwdIdx, firstSlot int) {
	n := 0
	slot := 0
	for _, path := range pwd.paths {
		if pwd.pm.useBestEffort {
			if path.updated || path.enabled {
				n = slot
			}
			pwd.pushBestEffortPath(&path, firstSlot+slot)
			slot += 1
		}

		if path.sbrWs != nil {
			if path.updated || path.enabled {
				n = slot
			}
			pwd.pushSibraPath(&path, firstSlot+slot)
			slot += 1
		}
		path.updated = false
	}
	pwd.pm.cNumPathsPerDst[pwdIdx] = C.int(n + 1)
}

func (pwd *PathsToDestination) pushBestEffortPath(path *PathMeta, slot int) {
	if path.updated {
		herculesPath, err := pwd.preparePath(&path.path)
		if err != nil {
			log.Error(err.Error() + " - path disabled")
			pwd.pm.cPathsPerDest[slot].enabled = false
			return
		}
		toCPath(*herculesPath, &pwd.pm.cPathsPerDest[slot], true, path.enabled)
	} else {
		pwd.pm.cPathsPerDest[slot].enabled = C.atomic_bool(path.enabled)
	}
}

func (pwd *PathsToDestination) pushSibraPath(path *PathMeta, slot int) {
	if path.sbrUpdated.Swap(false) || path.updated {
		herculesPath, err := pwd.preparePath(&path.path)
		if err != nil {
			log.Error(err.Error() + " - path disabled")
			pwd.pm.cPathsPerDest[slot].enabled = false
			return
		}
		sbrData := path.sbrWs.SyncResv.Load()
		// The worst thing that could happen due to decoupling the atomic sbrUpdated from the atomic
		// reference SyncResv is that we skip one version of the SIBRA Extension and copy the subsequent one
		// twice. That's fine.
		if sbrData.Ephemeral.BwCls > 0 { // build path header only if we actually get some bandwidth granted
			// TODO(sibra) put ws into herculesPath.SibraResv
			toCPath(*herculesPath, &pwd.pm.cPathsPerDest[slot], true, path.enabled && path.sbrEnabled.Load())
			// TODO(sibra) remove ws again
			pwd.pm.cPathsPerDest[slot].max_bps = C.u64(sbrData.Ephemeral.BwCls.Bps())
		} else { // no bandwidth: disable path
			pwd.pm.cPathsPerDest[slot].enabled = C.atomic_bool(false)
		}
	} else {
		pwd.pm.cPathsPerDest[slot].enabled = C.atomic_bool(path.enabled && path.sbrEnabled.Load())
	}
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
		log.Error(fmt.Sprintf("no paths to destination %s", pwd.addr.String()))
	}

	previousPathAvailable := make([]bool, pwd.pm.numPathsPerDst)
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
		for i, pathMeta := range pwd.paths {
			if newFingerprint == pathMeta.fingerprint {
				if !pathMeta.enabled {
					log.Info(fmt.Sprintf("[Destination %s] re-enabling path %d\n", pwd.addr.IA, i))
					pathMeta.enabled = true
					updated = true

					if pwd.pm.sibraMgr != nil {
						err := pwd.initSibraPath(&pathMeta, i)
						if err != nil {
							log.Error("Could not initialize SIBRA: " + err.Error())
							pwd.modifyTime = time.Now()
							return updated
						}
					}
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
		pathMeta := pwd.paths[i]
		if inUse == false && pathMeta.enabled {
			log.Info(fmt.Sprintf("[Destination %s] disabling path %d\n", pwd.addr.IA, i))
			pathMeta.enabled = false
			if pwd.pm.sibraMgr != nil && pathMeta.sbrWs != nil {
				err := pwd.pm.sibraMgr.Unwatch(pathMeta.sbrWs)
				if err != nil {
					log.Error(err.Error())
				}
				pathMeta.sbrWs = nil
				pathMeta.sbrEnabled.Store(false)
			}
			updated = true
		}
	}
	return updated
}

func (pwd *PathsToDestination) chooseNewPaths(previousPathAvailable *[]bool, availablePaths *spathmeta.AppPathSet) bool {
	updated := false
	for i, slotInUse := range *previousPathAvailable {
		if slotInUse == false {
			// TODO choose paths more cleverly
			for _, newPath := range *availablePaths {
				// check if the path is already in use
				newFingerprint := newPath.Fingerprint()
				pathInUse := false
				for _, pathMeta := range pwd.paths {
					if pathMeta.fingerprint == newFingerprint {
						pathInUse = true
						break
					}
				}
				if pathInUse {
					continue
				}

				// use it from now on
				log.Info(fmt.Sprintf("[Destination %s] enabling path %d:\n\t%s\n", pwd.addr.IA, i, newPath))
				pwd.paths[i].path = newPath
				pwd.paths[i].fingerprint = newFingerprint
				pwd.paths[i].enabled = true
				pwd.paths[i].updated = true

				updated = true

				if pwd.pm.sibraMgr != nil {
					err := pwd.initSibraPath(&pwd.paths[i], i)
					if err != nil {
						log.Error("Could not initialize SIBRA: " + err.Error())
						pwd.modifyTime = time.Now()
						return updated
					}
				}
				break
			}
		}
	}
	return updated
}

func (pwd *PathsToDestination) preparePath(p *snet.Path) (*HerculesPath, error) {
	var err error
	curDst := pwd.addr.Copy()
	curDst.Path = (*p).Path()
	if err = curDst.Path.InitOffsets(); err != nil {
		return nil, err
	}

	curDst.NextHop = (*p).OverlayNextHop()

	path, err := prepareSCIONPacketHeader(pwd.pm.src, curDst, pwd.pm.iface)
	if err != nil {
		return nil, err
	}
	return path, nil
}

func (pwd *PathsToDestination) initSibraPath(path *PathMeta, idx int) error {
	ctx, cancelTimeout := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelTimeout()
	ws, err := pwd.pm.sibraMgr.WatchEphem(ctx, &resvmgr.EphemConf{
		PathConf: &resvmgr.PathConf{
			Paths: pwd.sp,
			Key:   path.fingerprint,
		},
		Destination: nil, // TODO(sibra) pass correct address for pwd.addr
		MinBWCls:    0,
		MaxBWCls:    sibra.Bps(pwd.pm.maxBps).ToBwCls(false),
	})
	if err != nil {
		return err
	}

	path.sbrWs = ws
	path.sbrEnabled.Store(true)
	path.sbrUpdated.Store(true)

	go pwd.watchSibra(path, idx)
	return nil
}

func (pwd *PathsToDestination) watchSibra(path *PathMeta, idx int) {
	for event := range path.sbrWs.Events {
		switch event.Code {
		case resvmgr.Quit:
			log.Debug(fmt.Sprintf("[Destination %s] Sibra resolver #%d quit", pwd.addr.IA, idx))
			path.sbrEnabled.Store(false)
			pwd.ExtnUpdated.Store(true)
			return
		case resvmgr.Error:
			log.Error(fmt.Sprintf("[Destination %s] Sibra resolver on path #%d: %s", pwd.addr.IA, idx, event.Error))
		case resvmgr.ExtnExpired, resvmgr.ExtnCleaned:
			log.Debug(fmt.Sprintf("[Destination %s] Sibra resolver #%d: expired or cleaned", pwd.addr.IA, idx))
			path.sbrEnabled.Store(false)
			pwd.ExtnUpdated.Store(true)
		case resvmgr.ExtnUpdated:
			log.Debug(fmt.Sprintf("[Destination %s] Sibra resolver %d updated path", pwd.addr.IA, idx))
			path.sbrUpdated.Store(true)
			pwd.ExtnUpdated.Store(true)
		}
	}
}
