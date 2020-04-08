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

package resvmgr

import (
	"fmt"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathmgr"
	"github.com/scionproto/scion/go/lib/snet"
	"hercules/mock_sibra/lib/sibra"
	"hercules/mock_sibra/syncresv"
)

const (
	// eventChanCap is the maximum number of events that can fit in the queue.
	eventChanCap uint64 = 1 << 10
	// quitChanCap is the maximum number of quits that can fit in the queue.
	quitChanCap uint64 = 1 << 10
	// refireChanCap is the maximum number of refires that can fit in the queue.
	refireChanCap uint64 = 10
	// reconnectInterval is the time between reconnection attempts if SCIOND fails.
	reconnectInterval = 1 * time.Second
	// steadyReqTimeout is the timeout for a steady request.
	steadyReqTimeout = 3 * time.Second
	// svcSbUpdateInterval is the time between updating sibra service address.
	svcSbUpdateInterval = 1 * time.Second
)

// PathConf holds the path information for the reservation manager.
type PathConf struct {
	// Paths is the path set.
	Paths *pathmgr.SyncPaths
	// Key is the key of the preferred path.
	Key snet.PathFingerprint
}

// EphemConf holds the ephemeral reservation information for the
// reservation manager.
type EphemConf struct {
	*PathConf
	Destination addr.HostAddr
	MinBWCls    sibra.BwCls
	MaxBWCls    sibra.BwCls
}

// WatchState is the state for a reservation which is being watched.
// This allows the client to access the updated reservations and receive
// important events through a channel.
type WatchState struct {
	// SyncResv is a store for the SIBRA extensions which is automatically
	// and atomically updated by the reservation manager.
	SyncResv *syncresv.Store
	// resvKey is the key the reservation manager assigned to the current
	// reservation.
	resvKey ResvKey
	// Events is a event channel which allows the reservation manager to
	// communicate important events to the client. E.g. the extension has
	// been updated or an error has occurred. After a Quit event is received,
	// the channel is closed and the reservation manager will no longer handle
	// the reservation.
	Events <-chan *Event
	// stopDrain is used to stop the drain go routine.
	stopDrain chan struct{}
}

// DrainEvents starts a go routine which reads from the events channel and
// drops the events. This must be called by a client if it does not read from
// the Events channel in order to avoid blocking. A quit channel can be provided
// in order to be notified when the Resolver quits, nil otherwise.
func (ws *WatchState) DrainEvents(quit chan<- struct{}) error {
	if ws.stopDrain != nil {
		return common.NewBasicError("Drain go routine already started", nil)
	}
	ws.stopDrain = make(chan struct{})
	go drain(ws.resvKey, ws.Events, ws.stopDrain, quit)
	return nil
}

func drain(key ResvKey, events <-chan *Event, stop <-chan struct{}, quit chan<- struct{}) {
	for {
		select {
		case <-stop:
			log.Debug("[WatchState Drain] Stopped")
			return
		case event := <-events:
			if event.Code == Quit {
				log.Debug("[WatchState Drain] Stopping", "code", event.Code,
					"key", key, "err", event.Error)
				if quit != nil {
					close(quit)
				}
				return
			}
			if event.Error != nil {
				log.Debug("[WatchState Drain] New event", "code", event.Code,
					"key", key, "err", event.Error)
			} else {
				log.Debug("[WatchState Drain] New event", "code", event.Code, "key", key)
			}
		}
	}
}

// StopDrain stops the draining go routine. The quit channel is not closed to
// avoid confusion about the reason the draining routine has stopped.
func (ws *WatchState) StopDrain() error {
	if ws.stopDrain == nil {
		return common.NewBasicError("No drain go routine started", nil)
	}
	close(ws.stopDrain)
	ws.stopDrain = nil
	return nil
}

// EventCode indicates the type of event that has occurred and is sent
// to the client.
type EventCode int

const (
	Quit EventCode = iota
	Error
	ExtnExpired
	ExtnUpdated
	ExtnCleaned
)

func (c EventCode) String() string {
	switch c {
	case Quit:
		return "Quit"
	case Error:
		return "Error"
	case ExtnExpired:
		return "Extension expired"
	case ExtnUpdated:
		return "Extension updated"
	case ExtnCleaned:
		return "Extension cleaned"
	}
	return fmt.Sprintf("UNKNOWN(%d)", c)
}

// Event is used to communicate important events to the client.
type Event struct {
	// Code is the type of event that has occurred.
	Code EventCode
	// Error is set in case the event is the result of an error.
	Error error
}

// quitSignal is used to send a quit event from the resolver to the
// reservation manager.
type quitSignal struct {
	key ResvKey
	err error
}
