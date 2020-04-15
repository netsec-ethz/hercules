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
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	log "github.com/inconshreveable/log15"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/hpkt"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/pathmgr"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spkt"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/vishvananda/netlink"
	"go.uber.org/atomic"
	"hercules/mock_sibra/resvmgr" // TODO replace this with real API once it becomes available
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

type HerculesPath struct {
	Header          []byte //!< C.HERCULES_MAX_HEADERLEN bytes
	PartialChecksum uint16 //SCION L4 checksum over header with 0 payload
	NeedsSync       bool
	Enabled         bool
}

type SibraHerculesPath struct {
	*HerculesPath
	ws				*resvmgr.WatchState
	MaxBps			uint64
}

type herculesStats = C.struct_hercules_stats

const (
	etherLen    int = 1500
	defaultNUMA int = 0
)

var (
	activeInterface *net.Interface // activeInterface remembers the chosen interface for callbacks from C
)

type arrayFlags []string

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
		enableSibra		 bool
		ifname           string
		localAddr        string
		maxRateLimit     int
		mode             string
		numPaths         int
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
	flag.Parse()

	if (transmitFilename == "") == (outputFilename == "") {
		return errors.New("Exactly one of -t or -o needs to be specified")
	}

	if !enableBestEffort && !enableSibra {
		return errors.New("Best-effort traffic and COLIBRI bandwidth reservations both disabled, don't know how to send data ...")
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
		return errors.New("Interface is not up")
	}

	local, err := parseSCIONAddrs(localAddr)
	if err != nil {
		return err
	}
	if local.Host.Port == 0 {
		return errors.New("You must specify a source port")
	}

	err = checkAssignedIP(iface, local.Host.IP)
	if err != nil {
		return err
	}

	xdpMode := getXDPMode(mode)

	if transmitFilename != "" {
		var remotes []*snet.UDPAddr
		for _, remoteAddr := range(remoteAddrs) {
			remote, err := parseSCIONAddrs(remoteAddr)
			if err != nil {
				return err
			}
			if remote.Host.Port == 0 {
				return errors.New("You must specify a destination port")
			}
			remotes = append(remotes, remote)
		}
		if len(remotes) == 0 {
			return errors.New("You must specify at least one destination")
		}
		return mainTx(transmitFilename, local, remotes, iface, queue, maxRateLimit, enablePCC, enableBestEffort, enableSibra, xdpMode, dumpInterval, numPaths)
	}
	return mainRx(outputFilename, local, iface, queue, xdpMode, dumpInterval)
}

func mainTx(filename string, src *snet.UDPAddr, dsts []*snet.UDPAddr, iface *net.Interface, queue int, maxRateLimit int, enablePCC, enableBestEffort, enableSibra bool, xdpMode int, dumpInterval time.Duration, numPaths int) (err error) {
	pm, err := initNewPathManager(numPaths, iface, dsts, src, enableBestEffort, enableSibra)
	if err != nil {
		return err
	}

	_, err = pm.choosePaths()
	if err != nil {
		return err
	}

	herculesInit(iface, src, queue)
	pm.pushPaths()

	go pm.syncPathsToC()
	go statsDumper(true, dumpInterval)
	go cleanupOnSignal()
	stats := herculesTx(filename, dsts, pm, maxRateLimit, enablePCC, xdpMode)
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
	for _ = range ticker.C {
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
	local_c := toCAddr(local)

	C.hercules_init(C.int(iface.Index), local_c, C.int(queue))
	activeInterface = iface
}

func herculesTx(filename string, destinations []*snet.UDPAddr, pm *PathManager, maxRateLimit int, enablePCC bool, xdpMode int) herculesStats {
	cfilename := C.CString(filename)
	defer C.free(unsafe.Pointer(cfilename))

	cdests := make([]C.struct_hercules_app_addr, len(destinations))
	for d, dest := range destinations {
		cdests[d] = toCAddr(dest)
	}
	return C.hercules_tx(cfilename, &cdests[0], &pm.cPathsPerDest[0], C.int(len(destinations)), &pm.cNumPathsPerDst[0], pm.cMaxNumPathsPerDst, C.int(maxRateLimit), C.bool(enablePCC), C.int(xdpMode))
}

// HerculesGetReplyPath creates a reply path header for the packet header in headerPtr with given length.
// Returns 0 iff successful.
// This function is exported to C and called to obtain a reply path to send NACKs from the receiver (slow path).
//export HerculesGetReplyPath
func HerculesGetReplyPath(headerPtr unsafe.Pointer, length C.int, replyPathStruct *C.struct_hercules_path) C.int {
	buf := C.GoBytes(headerPtr, length)
	replyPath, err := getReplyPathHeader(buf, activeInterface)
	if err != nil {
		log.Debug("HerculesGetReplyPath", "err", err)
		return 1
	}
	toCPath(*replyPath, replyPathStruct)
	return 0
}

func parseSCIONAddrs(scionAddr string) (*snet.UDPAddr, error) {
	return snet.ParseUDPAddr(scionAddr)
}

func getReplyPathHeader(buf []byte, iface *net.Interface) (*HerculesPath, error) {
	packet := gopacket.NewPacket(buf, layers.LayerTypeEthernet, gopacket.Default)
	if err := packet.ErrorLayer(); err != nil {
		return nil, fmt.Errorf("Error decoding some part of the packet: %v", err)
	}
	ip4 := packet.Layer(layers.LayerTypeIPv4)
	if ip4 == nil {
		return nil, errors.New("Error decoding IPv4 layer")
	}
	dstIP, srcIP := ip4.(*layers.IPv4).SrcIP, ip4.(*layers.IPv4).DstIP

	udp := packet.Layer(layers.LayerTypeUDP)
	if udp == nil {
		return nil, errors.New("Error decoding IPv4/UDP layer")
	}
	udpPayload := udp.(*layers.UDP).Payload
	udpDstPort, _ := udp.(*layers.UDP).SrcPort, udp.(*layers.UDP).DstPort

	if len(udpPayload) < 8 { // Guard against bug in ParseScnPkt
		return nil, errors.New("Error decoding SCION packet: payload too small")
	}

	var scionPkt spkt.ScnPkt
	// XXX: ignore checksum errors. No API to parse without payload validation
	if err := hpkt.ParseScnPkt(&scionPkt, udpPayload); err != nil {
		return nil, fmt.Errorf("Error decoding SCION packet: %v", err)
	}

	scionPkt.DstIA, scionPkt.SrcIA = scionPkt.SrcIA, scionPkt.DstIA
	scionPkt.DstHost, scionPkt.SrcHost = scionPkt.SrcHost, scionPkt.DstHost

	if scionPkt.Path != nil {
		if err := scionPkt.Path.Reverse(); err != nil {
			return nil, fmt.Errorf("Failed to reverse SCION path: %v", err)
		}
		log.Debug("getReplyPathHeader", "path", scionPkt.Path)
	} else {
		log.Debug("getReplyPathHeader", "path", "No SCION Path header, source and destination in same AS.")
	}

	if scionPkt.L4 == nil {
		return nil, errors.New("Error decoding SCION/UDP")
	}
	scionPkt.L4.Reverse()

	overlayHeader, err := prepareOverlayPacketHeader(srcIP, dstIP, uint16(udpDstPort), iface)

	scionHeaderLen := scionPkt.HdrLen() + l4.UDPLen
	payloadLen := etherLen - len(overlayHeader) - scionHeaderLen
	scionPkt.Pld = common.RawBytes(make([]byte, payloadLen))

	scionHeader := make([]byte, etherLen)
	_, err = hpkt.WriteScnPkt(&scionPkt, scionHeader) // XXX: writes bogus L4 checksum
	if err != nil {
		return nil, err
	}
	scionHeader = scionHeader[:scionHeaderLen]
	scionChecksum := binary.LittleEndian.Uint16(scionPkt.L4.GetCSum())
	headerBuf := append(overlayHeader, scionHeader...)
	herculesPath := HerculesPath{
		Header:          headerBuf,
		PartialChecksum: scionChecksum,
	}
	return &herculesPath, nil
}

func toCPath(from HerculesPath, to *C.struct_hercules_path) {
	if len(from.Header) > C.HERCULES_MAX_HEADERLEN {
		panic(fmt.Sprintf("Header too long (%d), can't invoke hercules C API.", len(from.Header)))
	}
	to.headerlen = C.int(len(from.Header))
	to.payloadlen = C.int(etherLen - len(from.Header)) // TODO(matzf): take actual MTU into account, also when building header
	to.framelen = C.int(etherLen)                      // TODO(matzf): "
	// XXX(matzf): is there a nicer way to do this?
	C.memcpy(unsafe.Pointer(&to.header[0]),
		unsafe.Pointer(&from.Header[0]),
		C.ulong(len(from.Header)))
	to.checksum = C.ushort(from.PartialChecksum)
	to.replaced = C.atomic_bool(from.NeedsSync)
	to.enabled = C.atomic_bool(from.Enabled)
	to.max_bps = 0
}

func toCPathWithSibra(from SibraHerculesPath, to *C.struct_hercules_path) {
	toCPath(*from.HerculesPath, to)
	to.max_bps = C.u64(from.MaxBps)
}

func toCAddr(in *snet.UDPAddr) C.struct_hercules_app_addr {

	bufIA := make([]byte, 8)
	in.IA.Write(bufIA)
	bufIP := in.Host.IP.To4()
	bufPort := make([]byte, 2)
	binary.BigEndian.PutUint16(bufPort, uint16(in.Host.Port))

	out := C.struct_hercules_app_addr{}
	C.memcpy(unsafe.Pointer(&out.ia), unsafe.Pointer(&bufIA[0]), 8)
	C.memcpy(unsafe.Pointer(&out.ip), unsafe.Pointer(&bufIP[0]), 4)
	C.memcpy(unsafe.Pointer(&out.port), unsafe.Pointer(&bufPort[0]), 2)
	return out
}

func prepareSCIONPacketHeader(src, dst *snet.UDPAddr, iface *net.Interface) (*HerculesPath, error) {

	overlayHeader, err := prepareOverlayPacketHeader(src.Host.IP, dst.NextHop.IP, uint16(dst.NextHop.Port), iface)
	if err != nil {
		return nil, err
	}

	scionPkt := &spkt.ScnPkt{
		DstIA:   dst.IA,
		SrcIA:   src.IA,
		DstHost: addr.HostFromIP(dst.Host.IP),
		SrcHost: addr.HostFromIP(src.Host.IP),
		Path:    dst.Path,
		L4: &l4.UDP{
			SrcPort: uint16(src.Host.Port),
			DstPort: uint16(dst.Host.Port),
		},
	}
	scionHeaderLen := scionPkt.HdrLen() + l4.UDPLen
	payloadLen := etherLen - len(overlayHeader) - scionHeaderLen
	scionPkt.Pld = common.RawBytes(make([]byte, payloadLen))

	scionHeader := make([]byte, etherLen)
	_, err = hpkt.WriteScnPkt(scionPkt, scionHeader) // XXX: writes bogus L4 checksum
	if err != nil {
		return nil, err
	}
	scionHeader = scionHeader[:scionHeaderLen]
	scionChecksum := binary.LittleEndian.Uint16(scionPkt.L4.GetCSum())
	buf := append(overlayHeader, scionHeader...)
	herculesPath := HerculesPath{
		Header:          buf,
		PartialChecksum: scionChecksum,
	}
	return &herculesPath, nil
}

func prepareOverlayPacketHeader(srcIP, dstIP net.IP, dstPort uint16, iface *net.Interface) ([]byte, error) {
	dstMAC, srcMAC, err := getAddrs(iface, dstIP)
	if err != nil {
		return nil, err
	}

	ethHeader := 14
	ipHeader := 20
	udpHeader := 8

	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := layers.IPv4{
		Version:    4,
		IHL:        5, // Computed at serialization when FixLengths option set
		TOS:        0x0,
		Length:     uint16(etherLen - ethHeader), // Computed at serialization when FixLengths option set
		Id:         0,
		Flags:      layers.IPv4DontFragment,
		FragOffset: 0,
		TTL:        0xFF,
		Protocol:   layers.IPProtocolUDP,
		//Checksum: 0, // Set at serialization with the ComputeChecksums option
		SrcIP:   srcIP,
		DstIP:   dstIP,
		Options: nil,
	}

	srcPort := uint16(topology.EndhostPort)
	udp := layers.UDP{
		SrcPort:  layers.UDPPort(srcPort),
		DstPort:  layers.UDPPort(dstPort),
		Length:   uint16(etherLen - ethHeader - ipHeader),
		Checksum: 0,
	}

	buf := gopacket.NewSerializeBuffer()
	serializeOpts := gopacket.SerializeOptions{
		FixLengths:       false,
		ComputeChecksums: false,
	}
	serializeOptsChecked := gopacket.SerializeOptions{
		FixLengths:       false,
		ComputeChecksums: true,
	}
	err = serializeLayersWOpts(buf,
		layerWithOpts{&eth, serializeOpts},
		layerWithOpts{&ip, serializeOptsChecked},
		layerWithOpts{&udp, serializeOpts})
	if err != nil {
		return nil, err
	}

	// return only the headers
	return buf.Bytes()[:ethHeader+ipHeader+udpHeader], nil
}

type layerWithOpts struct {
	Layer gopacket.SerializableLayer
	Opts  gopacket.SerializeOptions
}

func serializeLayersWOpts(w gopacket.SerializeBuffer, layersWOpts ...layerWithOpts) error {
	w.Clear()
	for i := len(layersWOpts) - 1; i >= 0; i-- {
		layerWOpt := layersWOpts[i]
		err := layerWOpt.Layer.SerializeTo(w, layerWOpt.Opts)
		if err != nil {
			return err
		}
		w.PushLayer(layerWOpt.Layer.LayerType())
	}
	return nil
}

// getAddrs returns dstMAC, srcMAC and srcIP for a packet to be sent over interface to destination.
func getAddrs(iface *net.Interface, destination net.IP) (dstMAC, srcMAC net.HardwareAddr, err error) {

	srcMAC = iface.HardwareAddr

	// Get destination MAC (address of either destination or gateway) using netlink
	// n is the handle (i.e. the main entrypoint) for netlink
	n, err := netlink.NewHandle()
	if err != nil {
		return
	}
	defer n.Delete()

	routes, err := n.RouteGet(destination)
	if err != nil {
		return
	}
	route := routes[0]
	for _, r := range routes {
		if r.LinkIndex == iface.Index {
			route = r
			break
		}
	}
	if route.LinkIndex != iface.Index {
		err = errors.New("No route found to destination on specified interface")
	}

	dstIP := destination
	if route.Gw != nil {
		dstIP = route.Gw
	}
	dstMAC, err = getNeighborMAC(n, iface.Index, dstIP)
	if err != nil {
		if err.Error() == "Missing ARP entry" {
			// Handle missing ARP entry
			fmt.Printf("Sending ICMP echo to %v over %v and retrying...\n", dstIP, iface.Name)

			// Send ICMP
			if err = sendICMP(iface, route.Src, dstIP); err != nil {
				return
			}
			// Poll for 3 seconds
			for start := time.Now(); time.Since(start) < time.Duration(3)*time.Second; {
				dstMAC, err = getNeighborMAC(n, iface.Index, dstIP)
				if err == nil {
					break
				}
			}
		}
		if err != nil {
			return
		}
	}

	return
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// getNeighborMAC returns the HardwareAddr for the neighbor (ARP table entry) with the given IP
func getNeighborMAC(n *netlink.Handle, linkIndex int, ip net.IP) (net.HardwareAddr, error) {
	neighbors, err := n.NeighList(linkIndex, netlink.FAMILY_ALL)
	if err != nil {
		return nil, err
	}
	for _, neigh := range neighbors {
		if neigh.IP.Equal(ip) && neigh.HardwareAddr != nil {
			return neigh.HardwareAddr, nil
		}
	}
	return nil, errors.New("Missing ARP entry")
}

func sendICMP(iface *net.Interface, srcIP net.IP, dstIP net.IP) (err error) {
	ip := layers.IPv4{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolICMPv4,
	}
	icmp := layers.ICMPv4{
		TypeCode: layers.ICMPv4TypeEchoRequest,
	}
	buf := gopacket.NewSerializeBuffer()
	serializeOpts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buf, serializeOpts, &ip, &icmp)

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		fmt.Println("Creating raw socket failed.")
		return err
	}
	defer syscall.Close(fd)
	dstIPRaw := [4]byte{}
	copy(dstIPRaw[:4], dstIP.To4())
	ipSockAddr := syscall.SockaddrInet4{
		Port: 0,
		Addr: dstIPRaw,
	}
	if err = syscall.Sendto(fd, buf.Bytes(), 0, &ipSockAddr); err != nil {
		fmt.Printf("Sending ICMP echo to %v over %v failed.\n", dstIP, iface.Name)
		return err
	}
	return nil
}

func checkAssignedIP(iface *net.Interface, localAddr net.IP) (err error) {
	// Determine src IP matches information on Interface
	interfaceAddrs, err := iface.Addrs()
	if err != nil {
		return
	}
	for _, addr := range interfaceAddrs {
		ip, ok := addr.(*net.IPNet)
		if ok && ip.IP.To4() != nil && ip.IP.To4().Equal(localAddr) {
			return nil
		}
	}
	return errors.New("Interface does not have the specified IPv4 address")
}


type PathPool struct {
	addr        *snet.UDPAddr
	sp          *pathmgr.SyncPaths
	modifyTime  time.Time
	ExtnUpdated atomic.Bool

	// we use np paths, on each path we may use best-effort traffic and bandwidth reservations
	bePaths  []*HerculesPath      // path information for best-effort traffic
	sbrPaths []*SibraHerculesPath // path information for bandwidth reservations
	pathKeys []snet.PathFingerprint
}

func (pp *PathPool) watchSibra(p int) {
	path := pp.sbrPaths[p]
	for event := range path.ws.Events {
		switch event.Code {
		case resvmgr.Quit:
			log.Debug(fmt.Sprintf("[PathPool %s] Sibra resolver #%d quit", pp.addr.IA, p))
			path.Enabled = false
			pp.ExtnUpdated.Swap(true)
			return
		case resvmgr.Error:
			log.Error(fmt.Sprintf("[PathPool %s] Sibra resolver on path #%d: %s", pp.addr.IA, p, event.Error))
		case resvmgr.ExtnExpired, resvmgr.ExtnCleaned:
			log.Debug(fmt.Sprintf("[PathPool %s] Sibra resolver #%d: expired or cleaned", pp.addr.IA, p))
			path.Enabled = false
			pp.ExtnUpdated.Swap(false)
		case resvmgr.ExtnUpdated:
			log.Debug(fmt.Sprintf("[PathPool %s] Sibra resolver %d updated path", pp.addr.IA, p))
			sbrData := path.ws.SyncResv.Load()
			// TODO(sibra) put ws into path.SibraResv
			path.MaxBps = uint64(sbrData.Ephemeral.BwCls.Bps())
			if path.MaxBps == 0 {
				path.Enabled = false
			} else {
				path.Enabled = true
			}
			path.NeedsSync = true
			pp.ExtnUpdated.Swap(true)
		}
	}
}

type PathManager struct {
	numPathsPerDst     int
	iface              *net.Interface
	dsts               []*PathPool
	src                *snet.UDPAddr
	cNumPathsPerDst    []C.int
	cMaxNumPathsPerDst C.int
	cPathsPerDest      []C.struct_hercules_path
	syncTime           time.Time
	sibraMgr           *resvmgr.Mgr
	useBestEffort      bool
}

func initNewPathManager(numPathsPerDst int, iface *net.Interface, dsts []*snet.UDPAddr, src *snet.UDPAddr, enableBestEffort, enableSibra bool) (*PathManager, error) {
	var dstStates = make([]*PathPool, 0, numPathsPerDst)
	sciondConn, err := sciond.NewService(sciond.DefaultSCIONDAddress).Connect(context.Background())
	if err != nil {
		return nil, err
	}
	resolver := pathmgr.New(sciondConn, pathmgr.Timers{}, uint16(numPathsPerDst))
	for _, dst := range dsts {
		var dstState *PathPool
		if src.IA == dst.IA {
			if !enableBestEffort {
				return nil, errors.New(fmt.Sprintf("Can only use best-effort traffic to destination %s", dst))
			}
			if enableSibra {
				log.Warn("Can not use bandwidth reservation to destination %s", dst)
			}

			// use static empty path
			hop := net.UDPAddr{
				IP: dst.Host.IP,
				Port: topology.EndhostPort,
			}

			path := dst.Copy()
			path.Path = nil
			path.NextHop = &hop
			herculesPath, err := prepareSCIONPacketHeader(src, path, iface)
			if err != nil {
				return nil, err
			}
			herculesPath.NeedsSync = true
			herculesPath.Enabled = true

			dstState = &PathPool{
				addr:       dst,
				sp:         nil,
				bePaths:    []*HerculesPath{herculesPath},
				sbrPaths:	nil,
				modifyTime: time.Now(),
			}
		} else {
			// monitor path changes
			sp, err := resolver.Watch(context.Background(), src.IA, dst.IA)
			if err != nil {
				return nil, err
			}
			dstState = &PathPool{
				addr:       dst,
				sp:         sp,
				bePaths:    make([]*HerculesPath, numPathsPerDst),
				sbrPaths:   make([]*SibraHerculesPath, numPathsPerDst),
				pathKeys:   make([]snet.PathFingerprint, numPathsPerDst),
				modifyTime: time.Unix(0, 0),
			}
		}
		dstStates = append(dstStates, dstState)
	}

	var sibraMgr *resvmgr.Mgr
	if enableSibra {
		// TODO(sibra) make connection
		// TODO(sibra) make store
		mgr, err := resvmgr.New(nil, nil, nil, nil)
		if err != nil {
			return nil, err
		}
		sibraMgr = mgr
	}

	slotFactor := 1
	if enableSibra && enableBestEffort {
		slotFactor = 2
	}
	return &PathManager{
		numPathsPerDst: numPathsPerDst,
		iface:          iface,
		dsts:           dstStates,
		src:            src,
		syncTime:       time.Unix(0, 0),
		useBestEffort:  enableBestEffort,
		sibraMgr:       sibraMgr,

		// allocate memory to pass paths to C
		cNumPathsPerDst: make([]C.int, len(dsts)),
		cMaxNumPathsPerDst: C.int(numPathsPerDst*slotFactor),
		cPathsPerDest:   make([]C.struct_hercules_path, len(dsts)*numPathsPerDst*slotFactor),
	}, nil
}

func (pm *PathManager) pushPaths() {
	C.acquire_path_lock()
	defer C.free_path_lock()
	syncTime := time.Now()

	// prepare and copy headers to C
	for d, dst := range pm.dsts {
		if pm.syncTime.After(dst.modifyTime) {
			continue
		}

		n := 0
		slot := 0
		for p := 0; p < pm.numPathsPerDst; p++ {
			if pm.useBestEffort {
				path := dst.bePaths[p]
				if path != nil {
					if path.NeedsSync || path.Enabled {
						n = slot
					}
					if path.NeedsSync {
						toCPath(*path, &pm.cPathsPerDest[d*pm.numPathsPerDst+slot])
						path.NeedsSync = false
					} else {
						pm.cPathsPerDest[d*pm.numPathsPerDst+slot].enabled = C.atomic_bool(path.Enabled)
					}
				}
				slot += 1
			}

			if pm.sibraMgr != nil && dst.sbrPaths != nil {
				path := dst.sbrPaths[p]
				if path != nil {
					if path.NeedsSync || path.Enabled {
						n = slot
					}
					if path.NeedsSync {
						toCPathWithSibra(*path, &pm.cPathsPerDest[d*pm.numPathsPerDst+slot])
						path.NeedsSync = false
					} else {
						pm.cPathsPerDest[d*pm.numPathsPerDst+slot].enabled = C.atomic_bool(path.Enabled)
						pm.cPathsPerDest[d*pm.numPathsPerDst+slot].max_bps = C.u64(path.MaxBps)
					}
				}
				slot += 1
			}
		}
		pm.cNumPathsPerDst[d] = C.int(n + 1)
	}

	pm.syncTime = syncTime
	C.push_hercules_tx_paths()
}

func preparePath(dst *PathPool, p *snet.Path, pm *PathManager) (*HerculesPath, error) {
	var err error
	curDst := dst.addr.Copy()
	curDst.Path = (*p).Path()
	if err = curDst.Path.InitOffsets(); err != nil {
		return nil, err
	}

	curDst.NextHop = (*p).OverlayNextHop()

	path, err := prepareSCIONPacketHeader(pm.src, curDst, pm.iface)
	if err != nil {
		return nil, err
	}

	path.NeedsSync = true
	path.Enabled = true
	return path, nil
}

func (pm *PathManager) putBePath(dst *PathPool, pathIdx int, p *snet.Path, key snet.PathFingerprint) error {
	path, err := preparePath(dst, p, pm)
	if err != nil {
		return err
	}

	dst.bePaths[pathIdx] = path
	dst.pathKeys[pathIdx] = key
	return nil
}

func (pm *PathManager) putSbrPath(dst *PathPool, pathIdx int, p *snet.Path, key snet.PathFingerprint, ws *resvmgr.WatchState) error {
	path, err := preparePath(dst, p, pm)
	if err != nil {
		return err
	}

	sbrData := ws.SyncResv.Load()
	// TODO(sibra) put ws into path.SibraResv
	sbrPath := SibraHerculesPath{path, ws, uint64(sbrData.Ephemeral.BwCls.Bps())}
	dst.sbrPaths[pathIdx] = &sbrPath
	dst.pathKeys[pathIdx] = key
	return nil
}

func (pm *PathManager) choosePaths() (bool, error) {
	updated := false
	for _, dst := range pm.dsts {
		if dst.sp == nil {
			continue
		}

		pathData := dst.sp.Load()
		if dst.modifyTime.After(pathData.ModifyTime) {
			if dst.ExtnUpdated.Swap(false) {
				dst.modifyTime = time.Now()
				updated = true
			}
			continue
		}

		availablePaths := pathData.APS
		if len(availablePaths) == 0 {
			return updated, errors.New(fmt.Sprintf("No paths to destination %s", dst.addr.String()))
		}

		dstModified := false
		// keep previous paths, if still available
		pathInUse := make([]bool, pm.numPathsPerDst)
		for _, path := range availablePaths {
			curKey := path.Fingerprint()
			for i, prevKey := range dst.pathKeys {
				if curKey == prevKey {
					if !dst.bePaths[i].Enabled {
						log.Info(fmt.Sprintf("[PathPool %s] re-enabling path %d\n", dst.addr.IA, i))
						if pm.useBestEffort {
							dst.bePaths[i].Enabled = true
							dstModified = true
						}

						if pm.sibraMgr != nil {
							err := pm.initSibraPath(dst, curKey, i, path)
							if err != nil {
								if dstModified {
									dst.modifyTime = time.Now()
									updated = true
								}
								return updated, err
							}
							dstModified = true
						}
					}
					pathInUse[i] = true
					break
				}
			}
		}

		// check for vanished paths
		for i, inUse := range pathInUse {
			if inUse == false && dst.bePaths[i] != nil && dst.bePaths[i].Enabled {
				log.Info(fmt.Sprintf("[PathPool %s] disabling path %d\n", dst.addr.IA, i))
				if pm.useBestEffort {
					dst.bePaths[i].Enabled = false
				}
				if pm.sibraMgr != nil && dst.sbrPaths != nil {
					err := pm.sibraMgr.Unwatch(dst.sbrPaths[i].ws)
					if err != nil {
						log.Error(err.Error())
					}
					dst.sbrPaths[i].Enabled = false
				}
				dstModified = true
			}
		}

		// Note: we keep the keys of vanished paths, in case they come back before we can replace them

		// fill empty path slots
		for i, slotInUse := range pathInUse {
			if slotInUse == false {
				// TODO choose paths more cleverly
				for _, path := range availablePaths {
					// check if the path is already in use
					curKey := path.Fingerprint()
					inUse := false
					for _, key := range dst.pathKeys {
						if key == curKey {
							inUse = true
							break
						}
					}
					if inUse {
						continue
					}

					// use it from now on
					log.Info(fmt.Sprintf("[PathPool %s] enabling path %d:\n\t%s\n", dst.addr.IA, i, path))
					if pm.useBestEffort {
						err := pm.putBePath(dst, i, &path, curKey)
						if err != nil {
							if dstModified {
								dst.modifyTime = time.Now()
								updated = true
							}
							return updated, err
						}
						dstModified = true
						pathInUse[i] = true
					}

					if pm.sibraMgr != nil {
						err := pm.initSibraPath(dst, curKey, i, path)
						if err != nil {
							if dstModified {
								dst.modifyTime = time.Now()
								updated = true
							}
							return updated, err
						}
						dstModified = true
						pathInUse[i] = true
					}
					break
				}
			}
		}

		if dstModified {
			dst.modifyTime = time.Now()
			updated = true
		}
	}
	return updated, nil
}

func (pm *PathManager) initSibraPath(dst *PathPool, pathFingerprint snet.PathFingerprint, p int, path snet.Path) error {
	ctx, cancelTimeout := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelTimeout()
	ws, err := pm.sibraMgr.WatchEphem(ctx, &resvmgr.EphemConf{
		PathConf: &resvmgr.PathConf{
			Paths: dst.sp,
			Key:   pathFingerprint,
		},
		Destination: nil, // TODO(sibra) pass correct address for dst.addr
		MinBWCls:    0,
		MaxBWCls:    5,
	})
	if err != nil {
		return err
	}

	err = pm.putSbrPath(dst, p, &path, pathFingerprint, ws)
	if err != nil {
		return err
	}
	go dst.watchSibra(p)
	return nil
}

func (pm *PathManager) syncPathsToC() {
	ticker := time.NewTicker(500 * time.Millisecond)
	for _ = range ticker.C {
		updated, err := pm.choosePaths()
		if err != nil {
			log.Error(fmt.Sprintf("Error while choosing paths: %s\n", err))
			continue
		}
		if !updated {
			// same paths as before
			continue
		}

		pm.pushPaths()
	}
}
