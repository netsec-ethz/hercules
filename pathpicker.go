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
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath/spathmeta"
)

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func makePathPicker(spec *[]PathSpec, pathSet *spathmeta.AppPathSet, numPaths int) *PathPicker {
	if len(*spec) == 0 {
		defaultSpec := make([]PathSpec, numPaths)
		spec = &defaultSpec
	}
	paths := make([]snet.Path, 0, len(*pathSet))
	for _, path := range *pathSet {
		paths = append(paths, path)
	}
	picker := &PathPicker{
		pathSpec:       spec,
		availablePaths: paths,
	}
	picker.reset(numPaths)
	return picker
}

func (picker *PathPicker) reset(numPaths int) {
	descriptor := make([]PathPickDescriptor, numPaths)
	for i, _ := range descriptor {
		descriptor[i].ruleIndex = -1
		descriptor[i].pathIndex = -1
	}
	picker.currentPathPick = descriptor
}

func (picker *PathPicker) maxRuleIdx() int {
	// rule indices are sorted ascending
	for idx := len(picker.currentPathPick) - 1; idx >= 0; idx++ {
		if picker.currentPathPick[idx].ruleIndex != -1 {
			return picker.currentPathPick[idx].ruleIndex
		}
	}
	return -1
}

func (picker *PathPicker) numPaths() int {
	numPaths := 0
	for _, pick := range picker.currentPathPick {
		if pick.pathIndex != -1 {
			numPaths++
		}
	}
	return numPaths
}

// Iterates to the next set of rules. Returns false, if no set of the appropriate size exists.
func (picker *PathPicker) nextRuleSet() bool {
	ret := picker.nextRuleSetIterate(len(picker.currentPathPick) - 1)
	if ret {
		for i, _ := range picker.currentPathPick {
			picker.currentPathPick[i].pathIndex = -1
		}
	}
	return ret
}

func (picker *PathPicker) nextRuleSetIterate(idx int) bool {
	if idx > 0 && picker.currentPathPick[idx].ruleIndex == -1 {
		if !picker.nextRuleSetIterate(idx - 1) {
			return false
		}
		picker.currentPathPick[idx].ruleIndex = picker.currentPathPick[idx-1].ruleIndex
	}
	ruleIdx := picker.currentPathPick[idx].ruleIndex + 1
	for true {
		if ruleIdx < len(*picker.pathSpec) {
			picker.currentPathPick[idx].ruleIndex = ruleIdx
			return true
		}
		// overflow
		if idx > 0 {
			if !picker.nextRuleSetIterate(idx - 1) {
				picker.currentPathPick[idx].ruleIndex = -1
				return false
			}
			ruleIdx = picker.currentPathPick[idx-1].ruleIndex + 1
		} else {
			break // cannot overflow, abort
		}
	}
	return false
}

// Iterates to the next allowed choice of paths. Returns false, if no next pick exists.
func (picker *PathPicker) nextPick() bool {
	return picker.nextPickIterate(len(picker.currentPathPick) - 1)
}

func (picker *PathPicker) nextPickIterate(idx int) bool {
	if idx > 0 && picker.currentPathPick[idx-1].pathIndex == -1 {
		if !picker.nextPickIterate(idx - 1) {
			return false
		}
	}
	for true {
		for pathIdx := picker.currentPathPick[idx].pathIndex + 1; pathIdx < len(picker.availablePaths); pathIdx++ {
			if !picker.isInUse(pathIdx, idx) && picker.matches(pathIdx, picker.currentPathPick[idx].ruleIndex) {
				picker.currentPathPick[idx].pathIndex = pathIdx
				return true
			}
		}
		// overflow
		if idx > 0 {
			picker.currentPathPick[idx].pathIndex = -1
			if !picker.nextPickIterate(idx - 1) {
				return false
			}
		} else {
			break // cannot overflow, abort
		}
	}
	return false
}

func (picker *PathPicker) matches(pathIdx, ruleIdx int) bool {
	pathSpec := (*picker.pathSpec)[ruleIdx]
	pathInterfaces := picker.availablePaths[pathIdx].Interfaces()
	idx := 0
	for _, iface := range pathSpec {
		for len(pathInterfaces) > idx && !iface.match(pathInterfaces[idx]) {
			idx++
		}
		if idx >= len(pathInterfaces) {
			return false
		}
	}
	return true
}

func (picker *PathPicker) isInUse(pathIdx, idx int) bool {
	for i, pick := range picker.currentPathPick {
		if i > idx {
			return false
		}
		if pick.pathIndex == pathIdx {
			return true
		}
	}
	return false
}

func (picker *PathPicker) disjointnessScore() int {
	interfaces := map[snet.PathInterface]int{}
	score := 0
	for _, pick := range picker.currentPathPick {
		for _, path := range picker.availablePaths[pick.pathIndex].Interfaces() {
			score -= interfaces[path]
			interfaces[path]++
		}
	}
	return score
}

func (picker *PathPicker) getPaths() []snet.Path {
	paths := make([]snet.Path, 0, len(picker.currentPathPick))
	for _, pick := range picker.currentPathPick {
		paths = append(paths, picker.availablePaths[pick.pathIndex])
	}
	return paths
}
