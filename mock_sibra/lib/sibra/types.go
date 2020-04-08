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

package sibra

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
)

const (
	// Version is the SIBRA Version number.
	// It is a 2-bit value to be used as (SCION ver, SIBRA ver).
	Version byte = 0

	// SteadyIDLen is the steady ID length.
	SteadyIDLen = 10
	// EphemIDLen is the ephemeral ID length.
	EphemIDLen = 16

	// NumIndexes is the number of different reservation indexes.
	NumIndexes = 16

	// TickInterval indicates how many seconds there are in a SIBRA tick.
	TickInterval = 4
	// TickDuration is the duration of a SIBRA tick.
	TickDuration = TickInterval * time.Second
	// MaxEphemTicks is the maximum lifetime of an ephemeral reservation.
	MaxEphemTicks = 4
	// MaxSteadyTicks is the maximum lifetime of a steady reservation.
	MaxSteadyTicks = 20 * MaxEphemTicks

	// BwFactor is the SIBRA bandwidth factor
	BwFactor = 16 * 1000

	// MaxRLC is the maximum request latency class. It equates to 4 seconds.
	MaxRLC RLC = 12
)

// ID is the SIBRA reservation id. It can either be a steady id
// or an ephemeral id.
type ID common.RawBytes

func NewSteadyID(as addr.AS, idx uint32) ID {
	r := make(ID, SteadyIDLen)
	common.Order.PutUint16(r[:2], uint16((as>>32)&0xFFFF))
	common.Order.PutUint32(r[2:6], uint32(as&0xFFFFFFFF))
	common.Order.PutUint32(r[6:], idx)
	return r
}

func NewEphemID(as addr.AS, idx common.RawBytes) ID {
	r := make(ID, EphemIDLen)
	common.Order.PutUint16(r[:2], uint16((as>>32)&0xFFFF))
	common.Order.PutUint32(r[2:6], uint32(as&0xFFFFFFFF))
	copy(r[6:], idx)
	return r
}

func NewEphemIDRand(as addr.AS) ID {
	r := make(ID, EphemIDLen)
	common.Order.PutUint16(r[:2], uint16((as>>32)&0xFFFF))
	common.Order.PutUint32(r[2:6], uint32(as&0xFFFFFFFF))
	common.Order.PutUint64(r[6:14], rand.Uint64())
	common.Order.PutUint16(r[14:16], uint16(rand.Uint32()))
	return r
}

func (i ID) Len() int {
	return len(i)
}

func (i ID) Write(b common.RawBytes) error {
	if len(b) < len(i) {
		return common.NewBasicError("Buffer to short", nil, "method", "ID.Write",
			"min", len(i), "actual", len(b))
	}
	copy(b, i)
	return nil
}

func (i ID) Copy() ID {
	b := make(ID, len(i))
	copy(b, i)
	return b
}

func (i ID) String() string {
	if len(i) == 0 {
		return "None"
	}
	if len(i) >= SteadyIDLen {
		as := addr.AS(common.Order.Uint16(i[:2])) << 32
		as |= addr.AS(common.Order.Uint32(i[2:6]))
		switch len(i) {
		case SteadyIDLen:
			return fmt.Sprintf("%s-%d", as, common.Order.Uint32(i[6:SteadyIDLen]))
		case EphemIDLen:
			return fmt.Sprintf("%s-%x", as, []byte(i[6:]))
		}
	}
	return fmt.Sprintf("UNKNOWN(%x)", []byte(i))
}

func (i ID) Eq(o ID) bool {
	return bytes.Equal(i, o)
}

// Tick is the time unit used in SIBRA.
type Tick uint32

func CurrentTick() Tick {
	return TimeToTick(time.Now())
}

func TimeToTick(t time.Time) Tick {
	return Tick(t.Unix() / TickInterval)
}

func (t Tick) Time() time.Time {
	return time.Unix(TickInterval*int64(t), 0)
}

// Sub returns the difference between the tick and the provided one
// by subtracting other from this.
func (t Tick) Sub(other Tick) int {
	return int(t - other)
}

func (t Tick) Add(diff int) Tick {
	return t + Tick(diff)
}

// Bps is the type for handling bandwidth.
type Bps int64

func (b Bps) ToBwCls(floor bool) BwCls {
	bps := float64(b)
	if bps == 0 || (floor && bps < BwFactor) {
		return 0
	}
	base := math.Max(1, bps/BwFactor)
	cls := math.Log2(math.Pow(base, 2)) + 1
	if floor {
		return BwCls(math.Floor(cls))
	}
	return BwCls(math.Ceil(cls))
}

func (b Bps) String() string {
	bps := float64(b)
	mag := 0
	for ; bps > 1000 && mag < 4; mag++ {
		bps /= 1000
	}
	prefix := ""
	switch mag {
	case 1:
		prefix = "K"
	case 2:
		prefix = "M"
	case 3:
		prefix = "G"
	case 4:
		prefix = "T"
	}
	return fmt.Sprintf("%.3f %sbps", bps, prefix)
}

// BwCls is the SIBRA bandwidth class. It makes bandwidth discreet
// and is used to describe the bandwidth allocated for a reservation.
type BwCls uint8

func (b BwCls) Bps() Bps {
	if b == 0 {
		return 0
	}
	base := math.Sqrt(math.Pow(2, float64(b-1)))
	return Bps(math.Floor(BwFactor * base))
}

// RLC is the SIBRA request latency class. It allows an estimation how long
// a reservation request will take to travel to the end of the path
// and back including the processing times.
type RLC uint8

func (r RLC) Duration() time.Duration {
	// XXX(roosd): For testing purposes. Remove before putting in production.
	if r == 255 {
		return MaxEphemTicks * TickDuration
	}
	if r >= MaxRLC {
		return (1 << MaxRLC) * time.Millisecond
	}
	return (1 << r) * time.Millisecond
}

// DurationToRLC converts the duration to the RLC. The RLC is capped by MaxRLC.
func DurationToRLC(duration time.Duration, floor bool) RLC {
	ms := duration / time.Millisecond
	cls := math.Log2(float64(ms))
	val := RLC(math.Ceil(cls))
	if floor {
		val = RLC(math.Floor(cls))
	}
	if val > MaxRLC {
		return MaxRLC
	}
	return val
}

// Index is the reservation index. It allows multiple versions of a
// reservation for the same reservation id.
type Index uint8

func (i Index) Add(diff int) Index {
	return Index((int(i) + diff) % NumIndexes)
}

const (
	StateTemp State = iota
	StatePending
	StateActive
	StateVoid
)

// State is the reservation state.
type State uint8

func (s State) String() string {
	switch s {
	case StateTemp:
		return "Temporary"
	case StatePending:
		return "Pending"
	case StateActive:
		return "Active"
	case StateVoid:
		return "Void"
	}
	return fmt.Sprintf("UNKNOWN (%d)", s)
}

// SplitCls indicates the split between steady control and ephemeral traffic
// inside a steady tube.
type SplitCls uint8

func (c SplitCls) CtrlFctr() float64 {
	return 1 / math.Sqrt(float64(int(1<<c)))
}

func (c SplitCls) EphemFctr() float64 {
	return 1 - c.CtrlFctr()
}

const (
	TelescopeBase EndProps = 0x80
	StartLocal    EndProps = 0x10
	StartTransfer EndProps = 0x20
	EndLocal      EndProps = 0x01
	EndTransfer   EndProps = 0x02

	TeleBase = "B"
	Start    = "Start"
	End      = "End"
	Local    = "L"
	Transfer = "T"
)

// EndProps indicates the path-end properties.
type EndProps uint8

func (e EndProps) StartLocal() bool {
	return (e & StartLocal) != 0
}

func (e EndProps) StartTransfer() bool {
	return (e & StartTransfer) != 0
}

func (e EndProps) EndLocal() bool {
	return (e & EndLocal) != 0
}

func (e EndProps) EndTransfer() bool {
	return (e & EndTransfer) != 0
}

func (e EndProps) TelescopeBase() bool {
	return (e & TelescopeBase) != 0
}

func EndPropsFromMap(m map[string][]string) EndProps {
	var props EndProps
	for k, v := range m {
		for _, s := range v {
			switch {
			case k == Start && s == Local:
				props |= StartLocal
			case k == Start && s == Transfer:
				props |= StartTransfer
			case k == End && s == Local:
				props |= EndLocal
			case k == End && s == Transfer:
				props |= EndTransfer
			case s == TeleBase:
				props |= TelescopeBase
			}
		}
	}
	return props
}

func (e *EndProps) UnmarshalJSON(data []byte) error {
	var m map[string][]string
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	*e = EndPropsFromMap(m)
	return nil
}
