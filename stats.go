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
	"math"
	"time"
)

type herculesStats struct {
	startTime uint64
	endTime   uint64
	now       uint64

	txNpkts uint64
	rxNpkts uint64

	filesize        uint64
	frameLen        uint32
	chunkLen        uint32
	totalChunks     uint32
	completedChunks uint32 //!< either number of acked (for sender) or received (for receiver) chunks

	rateLimit uint32
}

type aggregateStats struct {
	maxPps     float64
	maxBpsThru float64
	maxBpsGood float64
}

func statsDumper(session *HerculesSession, tx bool, interval time.Duration, aggregate *aggregateStats) {
	if interval == 0 {
		return
	}

	statsAwaitStart(session)

	if tx {
		fmt.Printf("\n%-6s %10s %10s %20s %20s %20s %11s %11s\n",
			"Time",
			"Completion",
			"Goodput",
			"Throughput now",
			"Throughput target",
			"Throughput avg",
			"Pkts sent",
			"Pkts rcvd",
		)
	} else {
		fmt.Printf("\n%-6s %10s %10s %20s %20s %11s %11s\n",
			"Time",
			"Completion",
			"Goodput",
			"Throughput now",
			"Throughput avg",
			"Pkts rcvd",
			"Pkts sent",
		)
	}

	prevStats := herculesGetStats(session)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		select {
		default:
			stats := herculesGetStats(session)

			// elapsed time in seconds
			t := stats.now
			if stats.endTime > 0 {
				t = stats.endTime
			}
			dt := float64(t-prevStats.now) / 1e9
			dttot := float64(t-stats.startTime) / 1e9

			chunklen := float64(stats.chunkLen)
			framelen := float64(stats.frameLen)
			completion := float64(stats.completedChunks) / float64(stats.totalChunks)

			if tx {

				ppsNow := float64(stats.txNpkts-prevStats.txNpkts) / dt
				ppsAvg := float64(stats.txNpkts) / dttot
				ppsTrg := float64(stats.rateLimit)

				bpsGoodNow := 8 * chunklen * ppsNow
				bpsThruNow := 8 * framelen * ppsNow
				bpsThruAvg := 8 * framelen * ppsAvg
				bpsThruTrg := 8 * framelen * ppsTrg

				fmt.Printf("%5.1fs %9.2f%% %10s %10s %9s %10s %9s %10s %9s %11d %11d\n",
					dttot,
					completion*100,
					humanReadable(bpsGoodNow, "bps"),
					humanReadable(bpsThruNow, "bps"),
					humanReadable(ppsNow, "pps"),
					humanReadable(bpsThruTrg, "bps"),
					humanReadable(ppsTrg, "pps"),
					humanReadable(bpsThruAvg, "bps"),
					humanReadable(ppsAvg, "pps"),
					stats.txNpkts,
					stats.rxNpkts,
				)
				aggregate.maxPps = math.Max(aggregate.maxPps, ppsNow)
				aggregate.maxBpsGood = math.Max(aggregate.maxBpsGood, bpsGoodNow)
				aggregate.maxBpsThru = math.Max(aggregate.maxBpsThru, bpsThruNow)
			} else {

				ppsNow := float64(stats.rxNpkts-prevStats.rxNpkts) / dt
				ppsAvg := float64(stats.rxNpkts) / dttot

				bpsGoodNow := 8 * chunklen * ppsNow
				bpsThruNow := 8 * framelen * ppsNow
				bpsThruAvg := 8 * framelen * ppsAvg

				fmt.Printf("%5.1fs %9.2f%% %10s %10s %9s %10s %9s %11d %11d\n",
					dttot,
					completion*100,
					humanReadable(bpsGoodNow, "bps"),
					humanReadable(bpsThruNow, "bps"),
					humanReadable(ppsNow, "pps"),
					humanReadable(bpsThruAvg, "bps"),
					humanReadable(ppsAvg, "pps"),
					stats.rxNpkts,
					stats.txNpkts,
				)
				aggregate.maxPps = math.Max(aggregate.maxPps, ppsNow)
				aggregate.maxBpsGood = math.Max(aggregate.maxBpsGood, bpsGoodNow)
				aggregate.maxBpsThru = math.Max(aggregate.maxBpsThru, bpsThruNow)
			}

			if stats.endTime > 0 || stats.startTime == 0 { // explicitly finished or already de-initialized
				return
			}
			prevStats = stats
		}
	}
}

// statsAwaitStart busy-waits until hercules_get_stats indicates that the transfer has started.
func statsAwaitStart(session *HerculesSession) {
	for {
		stats := herculesGetStats(session)
		if stats.startTime > 0 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func printSummary(stats herculesStats, aggregate aggregateStats) {

	dttot := float64(stats.endTime-stats.startTime) / 1e9
	filesize := stats.filesize
	goodputBytePS := float64(filesize) / dttot
	fmt.Printf("\nTransfer completed:\n  %-12s%10.3fs\n  %-12s%11s\n  %-13s%11s (%s)\n  %-11s%11.3f\n  %-11s%11.3f\n  %-13s%11s (%s)\n  %-13s%11s\n",
		"Duration:", dttot,
		"Filesize:", humanReadableSize(filesize, "B"),
		"Rate:", humanReadable(8*goodputBytePS, "b/s"), humanReadableSize(uint64(goodputBytePS), "B/s"),
		"Sent/Chunk:", float64(stats.txNpkts)/float64(stats.totalChunks),
		"Rcvd/Chunk:", float64(stats.rxNpkts)/float64(stats.totalChunks),
		"Max thr.put:", humanReadable(aggregate.maxBpsThru, "b/s"), humanReadable(aggregate.maxPps, "P/s"),
		"Max goodput:", humanReadable(aggregate.maxBpsGood, "b/s"),
	)
}

func humanReadable(n float64, unit string) string {
	switch {
	case n >= 1e9:
		return fmt.Sprintf("%.1fG%s", n/1e9, unit)
	case n >= 1e6:
		return fmt.Sprintf("%.1fM%s", n/1e6, unit)
	default:
		return fmt.Sprintf("%.1fK%s", n/1e3, unit)
	}
}

func humanReadableSize(n uint64, unit string) string {
	const (
		Ki = 1 << 10
		Mi = 1 << 20
		Gi = 1 << 30
		Ti = 1 << 40
	)

	switch {
	case n >= Ti:
		return fmt.Sprintf("%.1fTi%s", float64(n)/float64(Ti), unit)
	case n >= Gi:
		return fmt.Sprintf("%.1fGi%s", float64(n)/float64(Gi), unit)
	case n >= Mi:
		return fmt.Sprintf("%.1fMi%s", float64(n)/float64(Mi), unit)
	case n >= Ki:
		return fmt.Sprintf("%.1fKi", float64(n)/float64(Ki))
	default:
		return fmt.Sprintf("%d%s", n, unit)
	}
}
