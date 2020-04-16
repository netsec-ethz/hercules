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
	log "github.com/inconshreveable/log15"
	"hercules/mock_sibra/resvmgr" // TODO replace this with real API once it becomes available
)

func (pp *PathPool) watchSibra(p int) {
	path := pp.sbrPaths[p]
	for event := range path.ws.Events {
		switch event.Code {
		case resvmgr.Quit:
			log.Debug(fmt.Sprintf("[PathPool %s] Sibra resolver #%d quit", pp.addr.IA, p))
			path.Enabled = false
			pp.ExtnUpdated.Swap(true)
			return
		case resvmgr.Error:
			log.Error(fmt.Sprintf("[PathPool %s] Sibra resolver on path #%d: %s", pp.addr.IA, p, event.Error))
		case resvmgr.ExtnExpired, resvmgr.ExtnCleaned:
			log.Debug(fmt.Sprintf("[PathPool %s] Sibra resolver #%d: expired or cleaned", pp.addr.IA, p))
			path.Enabled = false
			pp.ExtnUpdated.Swap(false)
		case resvmgr.ExtnUpdated:
			log.Debug(fmt.Sprintf("[PathPool %s] Sibra resolver %d updated path", pp.addr.IA, p))
			sbrData := path.ws.SyncResv.Load()
			// TODO(sibra) put ws into path.SibraResv
			path.MaxBps = uint64(sbrData.Ephemeral.BwCls.Bps())
			if path.MaxBps == 0 {
				path.Enabled = false
			} else {
				path.Enabled = true
			}
			path.NeedsSync = true
			pp.ExtnUpdated.Swap(true)
		}
	}
}
