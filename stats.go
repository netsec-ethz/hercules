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

// #cgo CFLAGS: -O3 -Wall -DNDEBUG -D_GNU_SOURCE -march=broadwell -mtune=broadwell
// #cgo LDFLAGS: ${SRCDIR}/bpf/libbpf.a -lm -lelf -pthread -lz
// #pragma GCC diagnostic ignored "-Wunused-variable" // Hide warning in cgo-gcc-prolog
// #include "hercules.h"
// #include <linux/if_xdp.h>
// #include <stdint.h>
// #include <stdlib.h>
// #include <string.h>
import "C"
import (
	"fmt"
	"time"
)

func statsDumper(tx bool, interval time.Duration) {
	if interval == 0 {
		return
	}

	statsAwaitStart()

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

	prevStats := C.hercules_get_stats()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		select {
		default:
			stats := C.hercules_get_stats()

			// elapsed time in seconds
			t := stats.now
			if stats.end_time > 0 {
				t = stats.end_time
			}
			dt := float64(t-prevStats.now) / 1e9
			dttot := float64(t-stats.start_time) / 1e9

			chunklen := float64(stats.chunklen)
			framelen := float64(stats.framelen)
			completion := float64(stats.completed_chunks) / float64(stats.total_chunks)

			if tx {

				ppsNow := float64(stats.tx_npkts-prevStats.tx_npkts) / dt
				ppsAvg := float64(stats.tx_npkts) / dttot
				ppsTrg := float64(stats.rate_limit)

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
					uint(stats.tx_npkts),
					uint(stats.rx_npkts),
				)
			} else {

				ppsNow := float64(uint(stats.rx_npkts)-uint(prevStats.rx_npkts)) / dt
				ppsAvg := float64(stats.rx_npkts) / dttot

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
					uint(stats.rx_npkts),
					uint(stats.tx_npkts),
				)
			}

			if stats.end_time > 0 || stats.start_time == 0 { // explicitly finished or already de-initialized
				return
			}
			prevStats = stats
		}
	}
}

// statsAwaitStart busy-waits until hercules_get_stats indicates that the transfer has started.
func statsAwaitStart() {
	for {
		stats := C.hercules_get_stats()
		if stats.start_time > 0 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func printSummary(stats herculesStats) {

	dttot := float64(stats.end_time-stats.start_time) / 1e9
	filesize := uint64(stats.filesize)
	goodputBytePS := float64(filesize) / dttot
	fmt.Printf("\nTransfer completed:\n  %-12s%10.3fs\n  %-12s%11s\n  %-13s%11s (%s)\n  %-11s%11.3f\n  %-11s%11.3f\n",
		"Duration:", dttot,
		"Filesize:", humanReadableSize(filesize, "B"),
		"Rate:", humanReadable(8*goodputBytePS, "b/s"), humanReadableSize(uint64(goodputBytePS), "B/s"),
		"Sent/Chunk:", float64(stats.tx_npkts)/float64(stats.total_chunks),
		"Rcvd/Chunk:", float64(stats.rx_npkts)/float64(stats.total_chunks),
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
