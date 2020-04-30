// Copyright 2018 ETH Zurich
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

// Package syncresv provides primitives for a SIBRA extension store
// which allows atomic updates of the extensions.
package syncresv

import (
	"hercules/mock_sibra/lib/sibra"
	"sync"
	"sync/atomic"
	"time"
)

// Store holds a Data value which is updated atomically.
type Store struct {
	value atomic.Value
	// Used to avoid races between multiple writers
	mutex sync.Mutex
}

type Mock struct {
	BwCls sibra.BwCls
}

func NewStore(ephem *Mock, steady *Mock) *Store {
	sp := &Store{}
	now := time.Now()
	sp.value.Store(
		&Data{
			Ephemeral:   ephem,
			Steady:      steady,
			ModifyTime:  now,
			RefreshTime: now,
		},
	)
	return sp
}

// UpdateEphem updates the ephemeral extension of the snapshot.
func (sp *Store) UpdateEphem(ephem *Mock) {
	sp.mutex.Lock()
	defer sp.mutex.Unlock()
	value := sp.Load()
	value.RefreshTime = time.Now()
	value.ModifyTime = value.RefreshTime
	value.Ephemeral = ephem
	sp.value.Store(value)
}

// UpdateSteady updates the steady extension of the snapshot.
func (sp *Store) UpdateSteady(steady *Mock) {
	sp.mutex.Lock()
	defer sp.mutex.Unlock()
	value := sp.Load()
	value.RefreshTime = time.Now()
	value.ModifyTime = value.RefreshTime
	value.Steady = steady
	sp.value.Store(value)
}

// Update updates both steady and ephemeral extension of the snapshot.
func (sp *Store) Update(ephem *Mock, steady *Mock) {
	sp.mutex.Lock()
	defer sp.mutex.Unlock()
	value := sp.Load()
	value.RefreshTime = time.Now()
	value.Ephemeral = ephem
	value.ModifyTime = value.RefreshTime
	value.Steady = steady
	sp.value.Store(value)
}

// Load returns a copy of the snapshot.
func (sp *Store) Load() *Data {
	val := *sp.value.Load().(*Data)
	return &val
}

// Data is the atomic value inside a Store object. It provides a
// snapshot of the extensions. Callers must not change the contents
// of the extensions.
type Data struct {
	Ephemeral   *Mock
	Steady      *Mock
	ModifyTime  time.Time
	RefreshTime time.Time
}
