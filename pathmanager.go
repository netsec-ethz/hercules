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
	var dstStates = make([]*PathPool, 0, numPathsPerDst)
	sciondConn, err := sciond.NewService(sciond.DefaultSCIONDAddress).Connect(context.Background())
	if err != nil {
		return nil, err
	}
	resolver := pathmgr.New(sciondConn, pathmgr.Timers{}, uint16(numPathsPerDst))
	for _, dst := range dsts {
		var dstState *PathPool
		if src.IA == dst.IA {
			if !enableBestEffort {
				return nil, errors.New(fmt.Sprintf("Can only use best-effort traffic to destination %s", dst))
			}
			if enableSibra {
				log.Warn("Can not use bandwidth reservation to destination %s", dst)
			}

			// use static empty path
			hop := net.UDPAddr{
				IP:   dst.Host.IP,
				Port: topology.EndhostPort,
			}

			path := dst.Copy()
			path.Path = nil
			path.NextHop = &hop
			herculesPath, err := prepareSCIONPacketHeader(src, path, iface)
			if err != nil {
				return nil, err
			}
			herculesPath.NeedsSync = true
			herculesPath.Enabled = true

			dstState = &PathPool{
				addr:       dst,
				sp:         nil,
				bePaths:    []*HerculesPath{herculesPath},
				sbrPaths:   nil,
				modifyTime: time.Now(),
			}
		} else {
			// monitor path changes
			sp, err := resolver.Watch(context.Background(), src.IA, dst.IA)
			if err != nil {
				return nil, err
			}
			dstState = &PathPool{
				addr:       dst,
				sp:         sp,
				bePaths:    make([]*HerculesPath, numPathsPerDst),
				sbrPaths:   make([]*SibraHerculesPath, numPathsPerDst),
				pathKeys:   make([]snet.PathFingerprint, numPathsPerDst),
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
		for p := 0; p < pm.numPathsPerDst; p++ {
			if pm.useBestEffort {
				path := dst.bePaths[p]
				if path != nil {
					if path.NeedsSync || path.Enabled {
						n = slot
					}
					if path.NeedsSync {
						toCPath(*path, &pm.cPathsPerDest[d*pm.numPathsPerDst+slot])
						path.NeedsSync = false
					} else {
						pm.cPathsPerDest[d*pm.numPathsPerDst+slot].enabled = C.atomic_bool(path.Enabled)
					}
				}
				slot += 1
			}

			if pm.sibraMgr != nil && dst.sbrPaths != nil {
				path := dst.sbrPaths[p]
				if path != nil {
					if path.NeedsSync || path.Enabled {
						n = slot
					}
					if path.NeedsSync {
						toCPathWithSibra(*path, &pm.cPathsPerDest[d*pm.numPathsPerDst+slot])
						path.NeedsSync = false
					} else {
						pm.cPathsPerDest[d*pm.numPathsPerDst+slot].enabled = C.atomic_bool(path.Enabled)
						pm.cPathsPerDest[d*pm.numPathsPerDst+slot].max_bps = C.u64(path.MaxBps)
					}
				}
				slot += 1
			}
		}
		pm.cNumPathsPerDst[d] = C.int(n + 1)
	}

	pm.syncTime = syncTime
	C.push_hercules_tx_paths()
}

func (pm *PathManager) preparePath(dst *PathPool, p *snet.Path) (*HerculesPath, error) {
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

	path.NeedsSync = true
	path.Enabled = true
	return path, nil
}

func (pm *PathManager) putBePath(dst *PathPool, pathIdx int, p *snet.Path, key snet.PathFingerprint) error {
	path, err := pm.preparePath(dst, p)
	if err != nil {
		return err
	}

	dst.bePaths[pathIdx] = path
	dst.pathKeys[pathIdx] = key
	return nil
}

func (pm *PathManager) putSbrPath(dst *PathPool, pathIdx int, p *snet.Path, key snet.PathFingerprint, ws *resvmgr.WatchState) error {
	path, err := pm.preparePath(dst, p)
	if err != nil {
		return err
	}

	sbrData := ws.SyncResv.Load()
	// TODO(sibra) put ws into path.SibraResv
	sbrPath := SibraHerculesPath{path, ws, uint64(sbrData.Ephemeral.BwCls.Bps())}
	dst.sbrPaths[pathIdx] = &sbrPath
	dst.pathKeys[pathIdx] = key
	return nil
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
		pathInUse := make([]bool, pm.numPathsPerDst)
		for _, path := range availablePaths {
			curKey := path.Fingerprint()
			for i, prevKey := range dst.pathKeys {
				if curKey == prevKey {
					if !dst.bePaths[i].Enabled {
						log.Info(fmt.Sprintf("[PathPool %s] re-enabling path %d\n", dst.addr.IA, i))
						if pm.useBestEffort {
							dst.bePaths[i].Enabled = true
							dstModified = true
						}

						if pm.sibraMgr != nil {
							err := pm.initSibraPath(dst, curKey, i, path)
							if err != nil {
								if dstModified {
									dst.modifyTime = time.Now()
									updated = true
								}
								return updated, err
							}
							dstModified = true
						}
					}
					pathInUse[i] = true
					break
				}
			}
		}

		// check for vanished paths
		for i, inUse := range pathInUse {
			if inUse == false && dst.bePaths[i] != nil && dst.bePaths[i].Enabled {
				log.Info(fmt.Sprintf("[PathPool %s] disabling path %d\n", dst.addr.IA, i))
				if pm.useBestEffort {
					dst.bePaths[i].Enabled = false
				}
				if pm.sibraMgr != nil && dst.sbrPaths != nil {
					err := pm.sibraMgr.Unwatch(dst.sbrPaths[i].ws)
					if err != nil {
						log.Error(err.Error())
					}
					dst.sbrPaths[i].Enabled = false
				}
				dstModified = true
			}
		}

		// Note: we keep the keys of vanished paths, in case they come back before we can replace them

		// fill empty path slots
		for i, slotInUse := range pathInUse {
			if slotInUse == false {
				// TODO choose paths more cleverly
				for _, path := range availablePaths {
					// check if the path is already in use
					curKey := path.Fingerprint()
					inUse := false
					for _, key := range dst.pathKeys {
						if key == curKey {
							inUse = true
							break
						}
					}
					if inUse {
						continue
					}

					// use it from now on
					log.Info(fmt.Sprintf("[PathPool %s] enabling path %d:\n\t%s\n", dst.addr.IA, i, path))
					if pm.useBestEffort {
						err := pm.putBePath(dst, i, &path, curKey)
						if err != nil {
							if dstModified {
								dst.modifyTime = time.Now()
								updated = true
							}
							return updated, err
						}
						dstModified = true
						pathInUse[i] = true
					}

					if pm.sibraMgr != nil {
						err := pm.initSibraPath(dst, curKey, i, path)
						if err != nil {
							if dstModified {
								dst.modifyTime = time.Now()
								updated = true
							}
							return updated, err
						}
						dstModified = true
						pathInUse[i] = true
					}
					break
				}
			}
		}

		if dstModified {
			dst.modifyTime = time.Now()
			updated = true
		}
	}
	return updated, nil
}

func (pm *PathManager) initSibraPath(dst *PathPool, pathFingerprint snet.PathFingerprint, p int, path snet.Path) error {
	ctx, cancelTimeout := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelTimeout()
	ws, err := pm.sibraMgr.WatchEphem(ctx, &resvmgr.EphemConf{
		PathConf: &resvmgr.PathConf{
			Paths: dst.sp,
			Key:   pathFingerprint,
		},
		Destination: nil, // TODO(sibra) pass correct address for dst.addr
		MinBWCls:    0,
		MaxBWCls:    sibra.Bps(pm.maxBps).ToBwCls(false),
	})
	if err != nil {
		return err
	}

	err = pm.putSbrPath(dst, p, &path, pathFingerprint, ws)
	if err != nil {
		return err
	}
	go dst.watchSibra(p)
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
