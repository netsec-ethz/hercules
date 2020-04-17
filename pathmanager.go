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
	"errors"
	"fmt"
	log "github.com/inconshreveable/log15"
	"github.com/scionproto/scion/go/lib/pathmgr"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/topology"
	"hercules/mock_sibra/lib/sibra"
	"hercules/mock_sibra/resvmgr" // TODO replace this with real API once it becomes available
	"net"
	"time"
)

func initNewPathManager(numPathsPerDst int, iface *net.Interface, dsts []*snet.UDPAddr, src *snet.UDPAddr, enableBestEffort, enableSibra bool, maxBps uint64) (*PathManager, error) {
	var dstStates = make([]*PathsToDestination, 0, numPathsPerDst)
	sciondConn, err := sciond.NewService(sciond.DefaultSCIONDAddress).Connect(context.Background())
	if err != nil {
		return nil, err
	}
	resolver := pathmgr.New(sciondConn, pathmgr.Timers{}, uint16(numPathsPerDst))
	for _, dst := range dsts {
		var dstState *PathsToDestination
		if src.IA == dst.IA {
			if !enableBestEffort {
				return nil, errors.New(fmt.Sprintf("Can only use best-effort traffic to destination %s", dst))
			}
			if enableSibra {
				log.Warn("Can not use bandwidth reservation to destination %s", dst)
			}

			// in order to use a static empty path, we need to set the next hop on dst
			dst.NextHop = &net.UDPAddr{
				IP:   dst.Host.IP,
				Port: topology.EndhostPort,
			}

			dstState = &PathsToDestination{
				addr: dst,
				sp:   nil,
				paths: []PathMeta{{
					enabled: true,
				}},
				modifyTime: time.Now(),
			}
		} else {
			// monitor path changes
			sp, err := resolver.Watch(context.Background(), src.IA, dst.IA)
			if err != nil {
				return nil, err
			}
			dstState = &PathsToDestination{
				addr:       dst,
				sp:         sp,
				paths:      make([]PathMeta, numPathsPerDst),
				modifyTime: time.Unix(0, 0),
			}
		}
		dstStates = append(dstStates, dstState)
	}

	var sibraMgr *resvmgr.Mgr
	if enableSibra {
		// TODO(sibra) make connection
		// TODO(sibra) make store
		mgr, err := resvmgr.New(nil, nil, nil, nil)
		if err != nil {
			return nil, err
		}
		sibraMgr = mgr
	}

	slotFactor := 1
	if enableSibra && enableBestEffort {
		slotFactor = 2
	}
	return &PathManager{
		numPathsPerDst: numPathsPerDst,
		iface:          iface,
		dsts:           dstStates,
		src:            src,
		syncTime:       time.Unix(0, 0),
		useBestEffort:  enableBestEffort,
		sibraMgr:       sibraMgr,
		maxBps:         maxBps,

		// allocate memory to pass paths to C
		cNumPathsPerDst:    make([]C.int, len(dsts)),
		cMaxNumPathsPerDst: C.int(numPathsPerDst * slotFactor),
		cPathsPerDest:      make([]C.struct_hercules_path, len(dsts)*numPathsPerDst*slotFactor),
	}, nil
}

func (pm *PathManager) pushPaths() {
	C.acquire_path_lock()
	defer C.free_path_lock()
	syncTime := time.Now()

	// prepare and copy headers to C
	for d, dst := range pm.dsts {
		if pm.syncTime.After(dst.modifyTime) {
			continue
		}

		n := 0
		slot := 0
		for _, path := range dst.paths {
			if pm.useBestEffort {
				if path.updated || path.enabled {
					n = slot
				}
				if path.updated {
					herculesPath, err := pm.preparePath(dst, &path.path)
					if err != nil {
						log.Error(err.Error())
						continue
					}
					toCPath(*herculesPath, &pm.cPathsPerDest[d*pm.numPathsPerDst+slot], true, path.enabled)
				} else {
					pm.cPathsPerDest[d*pm.numPathsPerDst+slot].enabled = C.atomic_bool(path.enabled)
				}
				slot += 1
			}

			if path.sbrWs != nil {
				if path.updated || path.enabled {
					n = slot
				}
				if path.sbrUpdated.Swap(false) || path.updated {
					herculesPath, err := pm.preparePath(dst, &path.path)
					if err != nil {
						log.Error(err.Error())
						continue
					}
					sbrData := path.sbrWs.SyncResv.Load()
					// The worst thing that could happen due to decoupling the atomic sbrUpdated from the atomic
					// reference SyncResv is that we skip one version of the SIBRA Extension and copy the subsequent one
					// twice. That's fine.
					if sbrData.Ephemeral.BwCls > 0 { // build path header only if we actually get some bandwidth granted
						// TODO(sibra) put ws into herculesPath.SibraResv
						toCPath(*herculesPath, &pm.cPathsPerDest[d*pm.numPathsPerDst+slot], true, path.enabled && path.sbrEnabled.Load())
						// TODO(sibra) remove ws again
						pm.cPathsPerDest[d*pm.numPathsPerDst+slot].max_bps = C.u64(sbrData.Ephemeral.BwCls.Bps())
					} else { // no bandwidth: disable path
						pm.cPathsPerDest[d*pm.numPathsPerDst+slot].enabled = C.atomic_bool(false)
					}
				} else {
					pm.cPathsPerDest[d*pm.numPathsPerDst+slot].enabled = C.atomic_bool(path.enabled && path.sbrEnabled.Load())
				}
				slot += 1
			}
			path.updated = false
		}
		pm.cNumPathsPerDst[d] = C.int(n + 1)
	}

	pm.syncTime = syncTime
	C.push_hercules_tx_paths()
}

func (pm *PathManager) preparePath(dst *PathsToDestination, p *snet.Path) (*HerculesPath, error) {
	var err error
	curDst := dst.addr.Copy()
	curDst.Path = (*p).Path()
	if err = curDst.Path.InitOffsets(); err != nil {
		return nil, err
	}

	curDst.NextHop = (*p).OverlayNextHop()

	path, err := prepareSCIONPacketHeader(pm.src, curDst, pm.iface)
	if err != nil {
		return nil, err
	}
	return path, nil
}

func (pm *PathManager) choosePaths() (bool, error) {
	updated := false
	for _, dst := range pm.dsts {
		if dst.sp == nil {
			continue
		}

		pathData := dst.sp.Load()
		if dst.modifyTime.After(pathData.ModifyTime) {
			if dst.ExtnUpdated.Swap(false) {
				dst.modifyTime = time.Now()
				updated = true
			}
			continue
		}

		availablePaths := pathData.APS
		if len(availablePaths) == 0 {
			return updated, errors.New(fmt.Sprintf("No paths to destination %s", dst.addr.String()))
		}

		dstModified := false
		// keep previous paths, if still available
		pathInUse := make([]bool, pm.numPathsPerDst) // TODO get rid of pathInUse?
		for _, newPath := range availablePaths {
			newFingerprint := newPath.Fingerprint()
			for i, pathMeta := range dst.paths {
				if newFingerprint == pathMeta.fingerprint {
					if !pathMeta.enabled {
						log.Info(fmt.Sprintf("[Destination %s] re-enabling path %d\n", dst.addr.IA, i))
						pathMeta.enabled = true
						dstModified = true

						if pm.sibraMgr != nil {
							err := pm.initSibraPath(dst, &pathMeta, i)
							if err != nil {
								dst.modifyTime = time.Now()
								return true, err
							}
						}
					}
					pathInUse[i] = true
					break
				}
			}
		}

		// check for vanished paths
		for i, inUse := range pathInUse {
			pathMeta := dst.paths[i]
			if inUse == false && pathMeta.enabled {
				log.Info(fmt.Sprintf("[Destination %s] disabling path %d\n", dst.addr.IA, i))
				pathMeta.enabled = false
				if pm.sibraMgr != nil && pathMeta.sbrWs != nil {
					err := pm.sibraMgr.Unwatch(pathMeta.sbrWs)
					if err != nil {
						log.Error(err.Error())
					}
					pathMeta.sbrWs = nil
					pathMeta.sbrEnabled.Store(false)
				}
				dstModified = true
			}
		}

		// Note: we keep the keys of vanished paths, in case they come back before we can replace them

		// fill empty path slots
		for i, slotInUse := range pathInUse {
			if slotInUse == false {
				// TODO choose paths more cleverly
				for _, newPath := range availablePaths {
					// check if the path is already in use
					newFingerprint := newPath.Fingerprint()
					inUse := false
					for _, pathMeta := range dst.paths {
						if pathMeta.fingerprint == newFingerprint {
							inUse = true
							break
						}
					}
					if inUse {
						continue
					}

					// use it from now on
					log.Info(fmt.Sprintf("[Destination %s] enabling path %d:\n\t%s\n", dst.addr.IA, i, newPath))
					dst.paths[i].path = newPath
					dst.paths[i].fingerprint = newFingerprint
					dst.paths[i].enabled = true
					dst.paths[i].updated = true

					dstModified = true
					pathInUse[i] = true

					if pm.sibraMgr != nil {
						err := pm.initSibraPath(dst, &dst.paths[i], i)
						if err != nil {
							dst.modifyTime = time.Now()
							return true, err
						}
					}
					break
				}
			}
		}

		if dst.ExtnUpdated.Swap(false) || dstModified {
			dst.modifyTime = time.Now()
			updated = true
		}
	}
	return updated, nil
}

func (pm *PathManager) initSibraPath(dst *PathsToDestination, path *PathMeta, idx int) error {
	ctx, cancelTimeout := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelTimeout()
	ws, err := pm.sibraMgr.WatchEphem(ctx, &resvmgr.EphemConf{
		PathConf: &resvmgr.PathConf{
			Paths: dst.sp,
			Key:   path.fingerprint,
		},
		Destination: nil, // TODO(sibra) pass correct address for dst.addr
		MinBWCls:    0,
		MaxBWCls:    sibra.Bps(pm.maxBps).ToBwCls(false),
	})
	if err != nil {
		return err
	}

	path.sbrWs = ws
	path.sbrEnabled.Store(true)
	path.sbrUpdated.Store(true)

	go dst.watchSibra(path, idx)
	return nil
}

func (pm *PathManager) syncPathsToC() {
	ticker := time.NewTicker(500 * time.Millisecond)
	for _ = range ticker.C {
		updated, err := pm.choosePaths()
		if err != nil {
			log.Error(fmt.Sprintf("Error while choosing paths: %s\n", err))
			continue
		}
		if !updated {
			// same paths as before
			continue
		}

		pm.pushPaths()
	}
}
