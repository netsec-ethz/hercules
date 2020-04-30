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

// #cgo CFLAGS: -std=c11 -O3 -Wall -DNDEBUG -D_GNU_SOURCE -march=broadwell -mtune=broadwell
// #cgo LDFLAGS: ${SRCDIR}/bpf/libbpf.a -lm -lelf -pthread
// #pragma GCC diagnostic ignored "-Wunused-variable" // Hide warning in cgo-gcc-prolog
// #include "hercules.h"
// #include <linux/if_xdp.h>
// #include <stdint.h>
// #include <stdlib.h>
// #include <string.h>
import "C"
import (
	"errors"
	"flag"
	"fmt"
	log "github.com/inconshreveable/log15"
	"github.com/scionproto/scion/go/lib/snet"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"
	"unsafe"
)

const (
	etherLen    int = 1500
)

var (
	activeInterface *net.Interface // activeInterface remembers the chosen interface for callbacks from C
)

func (i *arrayFlags) String() string {
	return "[\n\t\"" + strings.Join(*i, "\",\n\t\"") + "\"\n]"
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func main() {
	err := realMain()
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
}

func realMain() error {
	var (
		dumpInterval     time.Duration
		enablePCC        bool
		enableBestEffort bool
		enableSibra      bool
		ifname           string
		localAddr        string
		maxRateLimit     int
		mode             string
		numPaths         int
		numSendThreads   int
		queue            int
		remoteAddrs      arrayFlags
		transmitFilename string
		outputFilename   string
		verbose          string
	)
	// TODO(matzf): proper flag parsing (mandatory arguments, enforce --receive or --transmit, ...)
	flag.DurationVar(&dumpInterval, "n", time.Second, "Print stats at given interval")
	flag.BoolVar(&enablePCC, "pcc", true, "Enable performance-oriented congestion control (PCC)")
	flag.StringVar(&ifname, "i", "", "interface")
	flag.StringVar(&localAddr, "l", "", "local address")
	flag.IntVar(&maxRateLimit, "p", 3333333, "Maximum allowed send rate in Packets per Second (default: 3'333'333, ~40Gbps)")
	flag.StringVar(&mode, "m", "", "XDP socket bind mode (Zero copy: z; Copy mode: c)")
	flag.IntVar(&queue, "q", 0, "Use queue n")
	flag.Var(&remoteAddrs, "d", "destination host address(es)")
	flag.StringVar(&transmitFilename, "t", "", "transmit file (sender)")
	flag.StringVar(&outputFilename, "o", "", "output file (receiver)")
	flag.StringVar(&verbose, "v", "", "verbose output (from '' to vv)")
	flag.IntVar(&numPaths, "np", 1, "Maximum number of different paths per destination to use at the same time")
	flag.BoolVar(&enableBestEffort, "be", true, "Enable best-effort traffic")
	flag.BoolVar(&enableSibra, "resv", false, "Enable COLIBRI bandwidth reservations")
	flag.IntVar(&numSendThreads, "nt", 4, "Number of threads dedicated to send data")
	flag.Parse()

	if (transmitFilename == "") == (outputFilename == "") {
		return errors.New("exactly one of -t or -o needs to be specified")
	}

	if !enableBestEffort && !enableSibra {
		return errors.New("best-effort traffic and COLIBRI bandwidth reservations both disabled, don't know how to send data")
	}

	// Setup logger
	h := log.CallerFileHandler(log.StdoutHandler)
	if verbose == "vv" {
		log.Root().SetHandler(log.LvlFilterHandler(log.LvlDebug, h))
	} else if verbose == "v" {
		log.Root().SetHandler(log.LvlFilterHandler(log.LvlInfo, h))
	} else if verbose == "" {
		log.Root().SetHandler(log.LvlFilterHandler(log.LvlError, h))
	} else {
		return errors.New("-v can only be vv, v or empty")
	}

	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return err
	}
	if iface.Flags&net.FlagUp == 0 {
		return errors.New("interface is not up")
	}

	local, err := snet.ParseUDPAddr(localAddr)
	if err != nil {
		return err
	}
	if local.Host.Port == 0 {
		return errors.New("you must specify a source port")
	}

	err = checkAssignedIP(iface, local.Host.IP)
	if err != nil {
		return err
	}

	xdpMode := getXDPMode(mode)

	if transmitFilename != "" {
		var remotes []*snet.UDPAddr
		for _, remoteAddr := range remoteAddrs {
			remote, err := snet.ParseUDPAddr(remoteAddr)
			if err != nil {
				return err
			}
			if remote.Host.Port == 0 {
				return errors.New("you must specify a destination port")
			}
			remotes = append(remotes, remote)
		}
		if len(remotes) == 0 {
			return errors.New("you must specify at least one destination")
		}
		return mainTx(transmitFilename, local, remotes, iface, queue, maxRateLimit, enablePCC, enableBestEffort, enableSibra, xdpMode, dumpInterval, numPaths, numSendThreads)
	}
	return mainRx(outputFilename, local, iface, queue, xdpMode, dumpInterval)
}

func mainTx(filename string, src *snet.UDPAddr, dsts []*snet.UDPAddr, iface *net.Interface, queue int, maxRateLimit int, enablePCC, enableBestEffort, enableSibra bool, xdpMode int, dumpInterval time.Duration, numPaths int, numSendThreads int) (err error) {
	pm, err := initNewPathManager(numPaths, iface, dsts, src, enableBestEffort, enableSibra, uint64(maxRateLimit)*uint64(C.ETHER_SIZE))
	if err != nil {
		return err
	}

	pm.choosePaths()
	if !pm.canSendToAllDests() {
		return errors.New("some destinations are unreachable, abort")
	}

	herculesInit(iface, src, queue)
	pm.pushPaths()

	go pm.syncPathsToC()
	go statsDumper(true, dumpInterval)
	go cleanupOnSignal()
	stats := herculesTx(filename, dsts, pm, maxRateLimit, enablePCC, xdpMode, numSendThreads)
	printSummary(stats)
	return nil
}

func mainRx(filename string, local *snet.UDPAddr, iface *net.Interface, queue int, xdpMode int, dumpInterval time.Duration) error {

	filenamec := C.CString(filename)
	defer C.free(unsafe.Pointer(filenamec))

	herculesInit(iface, local, queue)
	go statsDumper(false, dumpInterval)
	go cleanupOnSignal()
	stats := C.hercules_rx(filenamec, C.int(xdpMode))
	printSummary(stats)
	return nil
}

func cleanupOnSignal() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, os.Kill)
	// Block until any signal is received.
	<-c
	C.hercules_close()
	os.Exit(128 + 15) // Customary exit code after SIGTERM
}

func getXDPMode(m string) (mode int) {
	switch m {
	case "z":
		mode = C.XDP_ZEROCOPY
	case "c":
		mode = C.XDP_COPY
	default:
		mode = 0
	}
	return mode
}

func herculesInit(iface *net.Interface, local *snet.UDPAddr, queue int) {
	localC := toCAddr(local)

	C.hercules_init(C.int(iface.Index), localC, C.int(queue))
	activeInterface = iface
}

func herculesTx(filename string, destinations []*snet.UDPAddr, pm *PathManager, maxRateLimit int, enablePCC bool, xdpMode int, numSendThreads int) herculesStats {
	cFilename := C.CString(filename)
	defer C.free(unsafe.Pointer(cFilename))

	cDests := make([]C.struct_hercules_app_addr, len(destinations))
	for d, dest := range destinations {
		cDests[d] = toCAddr(dest)
	}
	return C.hercules_tx(cFilename, &cDests[0], &pm.cPathsPerDest[0], C.int(len(destinations)), &pm.cNumPathsPerDst[0], pm.cMaxNumPathsPerDst, C.int(maxRateLimit), C.bool(enablePCC), C.int(xdpMode), C.int(numSendThreads))
}

func checkAssignedIP(iface *net.Interface, localAddr net.IP) (err error) {
	// Determine src IP matches information on Interface
	interfaceAddrs, err := iface.Addrs()
	if err != nil {
		return
	}
	for _, ifAddr := range interfaceAddrs {
		ip, ok := ifAddr.(*net.IPNet)
		if ok && ip.IP.To4() != nil && ip.IP.To4().Equal(localAddr) {
			return nil
		}
	}
	return errors.New("interface does not have the specified IPv4 address")
}
