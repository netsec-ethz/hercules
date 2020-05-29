// Copyright 2017 ETH Zurich
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
	"bufio"
	"errors"
	"fmt"
	"hercules/mock_sibra/lib/sibra"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"context"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/snet"
	"hercules/mock_sibra/syncresv"
)

// Timers is used to customize the timers for a reservation manager.
type Timers struct {
	// Wait time after a successful reservation operation.
	NormalRefire time.Duration
	// Wait time after a failed reservation operation.
	ErrorRefire time.Duration
}

const (
	// Default wait time after a successful reservation operation.
	DefaultNormalRefire = 4 * time.Second / 2
	// Default wait time after a failed reservation operation.
	DefaultErrorRefire = 100 * time.Millisecond
)

func setDefaultTimers(timers *Timers) {
	if timers.NormalRefire == 0 {
		timers.NormalRefire = DefaultNormalRefire
	}
	if timers.ErrorRefire == 0 {
		timers.ErrorRefire = DefaultErrorRefire
	}
}

// Mgr takes care of the SIRBA reservation setup and management. A client
// can request the manager to manage a best effort steady reservation to a
// remote destination or an ephemeral reservation with guaranteed bandwidth.
// The manager communicates important events to the client through the
// watch state.
type Mgr struct {
	log.Logger
	mu sync.Mutex
	// timers are the timers for refiring.
	timers *Timers
	// stopChans keeps track of the stop channels to the resolvers.
	stopChans map[ResvKey]chan struct{}
	// quitChan allows resolvers to notify the Mgr that they quit.
	quitChan chan quitSignal
	// closeChan allows the reservation manager to be gracefully shut down.
	closeChan chan struct{}
	// store holds the state of all reservations that are being watched.
	store *store
}

var idCounter uint32 = 0

func New(_ sciond.Connector, _ *snet.Conn, _ *trust.Store,
	timers *Timers) (*Mgr, error) {

	logger := log.New("mgrID", idCounter)
	idCounter += 1
	log.Info("(MOCK mode) Skipping reservation manager address check")

	if timers == nil {
		timers = &Timers{}
	}
	setDefaultTimers(timers)
	mgr := &Mgr{
		Logger:    logger,
		store:     newStore(),
		timers:    timers,
		stopChans: make(map[ResvKey]chan struct{}),
		quitChan:  make(chan quitSignal, quitChanCap),
	}
	go mgr.listenQuits()
	return mgr, nil
}

// WatchSteady starts a resolver that periodically updates the steady extension
// in the watch state. The extension can be used to send best effort traffic.
func (r *Mgr) WatchSteady(ctx context.Context, pconf *PathConf) (*WatchState, error) {
	syncResvs := syncresv.NewStore(nil, nil)
	entry := &resvEntry{
		paths:     pconf.Paths,
		pathKey:   pconf.Key,
		syncResv:  syncResvs,
		fixedPath: true,
	}
	resvKey, err := r.store.addResv(entry)
	if err != nil {
		return nil, err
	}
	return r.startResolverAndWait(ctx, syncResvs, resvKey)
}

// WatchEphem starts a resolver that periodically updates the steady and ephemeral
// extension in the watch state. The steady extension can be used to send best effort
// traffic. The ephemeral extension can be used to send guaranteed and best effort
// traffic.
func (r *Mgr) WatchEphem(ctx context.Context, econf *EphemConf) (*WatchState, error) {

	syncResvs := syncresv.NewStore(nil, nil)
	entry := &resvEntry{
		paths:     econf.Paths,
		pathKey:   econf.Key,
		syncResv:  syncResvs,
		fixedPath: true,
		ephemMeta: &ephemMeta{
			remote:   econf.Destination,
			minBwCls: econf.MinBWCls,
			maxBwCls: econf.MaxBWCls,
		},
	}
	resvKey, err := r.store.addResv(entry)
	if err != nil {
		return nil, err
	}
	return r.startResolverAndWait(ctx, syncResvs, resvKey)
}

func (r *Mgr) startResolverAndWait(ctx context.Context, sresvs *syncresv.Store,
	key ResvKey) (*WatchState, error) {

	return r.waitInitSetup(ctx, sresvs, key, r.startResolver(key, sresvs))
}

func (r *Mgr) startResolver(key ResvKey, sresvs *syncresv.Store) chan *Event {
	events := make(chan *Event, eventChanCap)
	stop := make(chan struct{})

	r.mu.Lock()
	defer r.mu.Unlock()
	r.stopChans[key] = stop
	// start mock resolver
	go r.resolve(key, events, stop, sresvs)

	return events
}

type socketToken struct {
	err 	error
	line 	*string
}

func sock2chan(conn net.Conn, lines chan socketToken) {
	scanner := bufio.NewScanner(conn)
	for {
		if !scanner.Scan() {
			lines <- socketToken{scanner.Err(), nil}
			break
		}
		line := scanner.Text()
		lines <- socketToken{nil, &line}
	}
}

func readLines(conn net.Conn, events chan *Event, stop chan struct{}, sresvs *syncresv.Store) {
	var err error
	lines := make(chan socketToken)
	go sock2chan(conn, lines)
	for {
		select {
		case <-stop:
			goto Quit
		case line := <-lines:
			if line.err != nil {
				events <- &Event{
					Code:  Error,
					Error: line.err,
				}
				close(stop)
				close(events)
				break
			}
			tokens := strings.Split(*line.line, " ")
			switch tokens[0] {
			case "GRANT":
				cls, err := strconv.ParseInt(tokens[1], 10, 32)
				if err != nil {
					events <- &Event{
						Code: Error,
						Error: err,
					}
				} else {
					bwCls := sibra.BwCls(cls)
					sresvs.UpdateEphem(&syncresv.Mock{BwCls: bwCls})
					events <- &Event{
						Code: ExtnUpdated,
					}
				}
			case "EXPIRE":
				close(stop)
				events <- &Event{Code: ExtnExpired}
				goto Quit
			case "CLEAN":
				close(stop)
				events <- &Event{Code: ExtnCleaned}
				goto Quit
			case "DROP":
				close(stop)
				events <- &Event{
					Code: Quit,
					Error: err,
				}
				goto Quit
			case "ERROR":
				events <- &Event{
					Code: ExtnExpired,
					Error: errors.New(strings.Join(tokens[1:], " ")),
				}
			default:
				events <- &Event{
					Code: ExtnExpired,
					Error: fmt.Errorf("could not parse line: %s", *line.line),
				}
			}
		}
	}

Quit:
	close(events)
}

func (r *Mgr) resolve(key ResvKey, events chan *Event, stop chan struct{}, sresvs *syncresv.Store) {
	// connect to the mock server
	var d net.Dialer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	conn, err := d.DialContext(ctx, "tcp", "localhost:10001")
	cancel()

	if err != nil {
		events <- &Event{
			Code:  Error,
			Error: err,
		}
		// TODO close resolver
		return
	}

	// place reservation
	resv := r.store.getResv(key)
	_, err = conn.Write([]byte(fmt.Sprintf("RESV %d %s\n", resv.ephemMeta.maxBwCls, resv.getPath())))
	if err != nil {
		events <- &Event{
			Code: Error,
			Error: err,
		}
		// TODO close resolver
		return
	}


	// wait for events
	go readLines(conn, events, stop, sresvs)
}

func (r *Mgr) waitInitSetup(ctx context.Context, sresvs *syncresv.Store,
	key ResvKey, events chan *Event) (*WatchState, error) {

	var err error
	select {
	case event := <-events:
		if event.Error != nil {
			err = event.Error
		}
	case <-ctx.Done():
		err = ctx.Err()
	}
	if err != nil {
		r.stopResolver(key)
		return nil, err
	}
	ws := &WatchState{
		resvKey:  key,
		Events:   events,
		SyncResv: sresvs,
	}
	return ws, nil
}

// Unwatch stops the resolver associated with the WatchState.
func (r *Mgr) Unwatch(ws *WatchState) error {
	return r.stopResolver(ws.resvKey)
}

// listenQuits listens for any quitting resolver and removes it from the mapping.
func (r *Mgr) listenQuits() {
	logger := r.New("goroutine", "resvmgr.listenQuits")
	for {
		select {
		case <-r.closeChan:
			return
		case qs := <-r.quitChan:
			if qs.err != nil {
				logger.Info("Resolver quit with error", "err", qs.err)
			}
			r.stopResolver(qs.key)
		}
	}
}

func (r *Mgr) stopResolver(key ResvKey) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if stop, ok := r.stopChans[key]; ok {
		select {
		case <-stop:
			// Channel is already closed
			return nil
		default:
			close(stop)
			delete(r.stopChans, key)
			return r.store.removeResv(key)
		}

	}
	return common.NewBasicError("Resolver already stopped or not found", nil, "key", key)
}


func (r *Mgr) Close() error {
	// Protect against concurrent Close calls
	r.mu.Lock()
	defer r.mu.Unlock()
	select {
	case <-r.closeChan:
		// Already closed, so do nothing
	default:
		close(r.closeChan)
		for _, c := range r.stopChans {
			close(c)
		}
		r.stopChans = nil
	}
	return nil
}
