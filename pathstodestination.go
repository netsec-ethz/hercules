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
