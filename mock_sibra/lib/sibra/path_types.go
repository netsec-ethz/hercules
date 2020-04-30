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
	"encoding"
	"fmt"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/proto"
)

var _ encoding.TextUnmarshaler = (*PathType)(nil)
var _ encoding.TextMarshaler = (*PathType)(nil)

// PathType indicates the type of path the packet is sent on.
type PathType uint8

const (
	PathTypeDown PathType = iota
	PathTypeUp
	PathTypePeerDown
	PathTypePeerUp
	PathTypeEphemeral
	PathTypeCore
	PathTypeNone
)

func PathTypeFromString(pt string) (PathType, error) {
	switch pt {
	case "Down":
		return PathTypeDown, nil
	case "Up":
		return PathTypeUp, nil
	case "Peering-Down":
		return PathTypePeerDown, nil
	case "Peering-Up":
		return PathTypePeerUp, nil
	case "Ephemeral":
		return PathTypeEphemeral, nil
	case "Core":
		return PathTypeCore, nil
	}
	return PathTypeNone, common.NewBasicError("Invalid path type", nil, "pt", pt)
}

// GenFwd indicates if the SIBRA opaque field are generated in the forward direction.
// This means the previous SOF is used for input during generation and validation.
// Otherwise, the next SOF is used as input. This is true for Down, PeerDown and Ephemeral paths.
func (t PathType) GenFwd() bool {
	return (t & 0x1) == 0
}

// Reversed indicates if the setup of the reservation is in the reverse direction.
// In a Down and peering Down reservation, the reservation initiator is the destination
// of the reservation.
func (t PathType) Reversed() bool {
	return t == PathTypeDown || t == PathTypePeerDown
}

// ValidAfter validates that the path type can be stiched after the supplied path type.
func (t PathType) ValidAfter(prev PathType) bool {
	switch prev {
	case PathTypeNone:
		return t != PathTypePeerDown && t != PathTypeNone
	case PathTypeUp:
		return t == PathTypeCore || t == PathTypeDown
	case PathTypePeerUp:
		return t == PathTypePeerDown
	case PathTypeCore:
		return t == PathTypeDown
	default: // PathTypeDown, PathTypePeerDown, PathTypeEphemeral
		return false
	}
}

func (t PathType) ValidIFPair(in, eg proto.LinkType) bool {
	switch t {
	case PathTypeDown:
		return ((in == proto.LinkType_unset || in == proto.LinkType_parent) &&
			eg == proto.LinkType_child) || (in == proto.LinkType_parent &&
			eg == proto.LinkType_unset)
	case PathTypeUp:
		return ((in == proto.LinkType_unset || in == proto.LinkType_child) &&
			eg == proto.LinkType_parent) || (in == proto.LinkType_child &&
			eg == proto.LinkType_unset)
	case PathTypePeerDown:
		return (in == proto.LinkType_unset && eg == proto.LinkType_peer) ||
			((in == proto.LinkType_peer || in == proto.LinkType_parent) &&
				(eg == proto.LinkType_unset || eg == proto.LinkType_child))
	case PathTypePeerUp:
		return ((in == proto.LinkType_unset || in == proto.LinkType_child) &&
			(eg == proto.LinkType_parent || eg == proto.LinkType_peer)) ||
			(in == proto.LinkType_peer && eg == proto.LinkType_unset)
	case PathTypeEphemeral:
		return !((in == proto.LinkType_parent && eg == proto.LinkType_parent) ||
			(in == proto.LinkType_peer && eg == proto.LinkType_peer))
	case PathTypeCore:
		return ((in == proto.LinkType_unset || in == proto.LinkType_core) &&
			eg == proto.LinkType_core) || (in == proto.LinkType_core &&
			eg == proto.LinkType_unset)
	}
	return false
}

func (t PathType) MarshalText() ([]byte, error) {
	if t > PathTypeCore {
		return nil, common.NewBasicError("Invalid PathType", nil, "type", t)
	}
	return []byte(t.String()), nil
}

// allows IA to be used as a map key in JSON.
func (t *PathType) UnmarshalText(text []byte) error {
	pt, err := PathTypeFromString(string(text))
	if err != nil {
		return err
	}
	*t = pt
	return nil
}

func (t PathType) String() string {
	switch t {
	case PathTypeDown:
		return "Down"
	case PathTypeUp:
		return "Up"
	case PathTypePeerDown:
		return "Peering-Down"
	case PathTypePeerUp:
		return "Peering-Up"
	case PathTypeEphemeral:
		return "Ephemeral"
	case PathTypeCore:
		return "Core"
	}
	return fmt.Sprintf("UNKNOWN (%d)", t)
}
