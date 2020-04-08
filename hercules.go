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
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/spkt"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/topology/overlay"
	"github.com/vishvananda/netlink"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
	"unsafe"
)

type HerculesPath struct {
	Header          []byte //!< C.HERCULES_MAX_HEADERLEN bytes
	PartialChecksum uint16 //SCION L4 checksum over header with 0 payload
}

type herculesStats = C.struct_hercules_stats

const (
	etherLen        int = 1500
	defaultNUMA     int = 0
	defaultUDP4Port int = 10000
)

var (
	activeInterface *net.Interface // activeInterface remembers the chosen interface for callbacks from C
)

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
		ifname           string
		localAddr        string
		maxRateLimit     int
		mode             string
		queue            int
		remoteAddr       string
		transmitFilename string
		outputFilename   string
		verbose          string
	)
	// TODO(matzf): proper flag parsing (mandatory arguments, enforce --receive or --transmit, ...)
	flag.DurationVar(&dumpInterval, "n", time.Second, "Print stats at given interval")
	flag.BoolVar(&enablePCC, "pcc", true, "Enable performance-oriented congestion control (PCC)")
	flag.StringVar(&ifname, "i", "", "interface")
	flag.StringVar(&localAddr, "b", "", "bind to local address")
	flag.IntVar(&maxRateLimit, "p", 3333333, "Maximum allowed send rate in Packets per Second (default: 3'333'333, ~40Gbps)")
	flag.StringVar(&mode, "m", "", "XDP socket bind mode (Zero copy: z; Copy mode: c)")
	flag.IntVar(&queue, "q", 0, "Use queue n")
	flag.StringVar(&remoteAddr, "d", "", "destination host address")
	flag.StringVar(&transmitFilename, "t", "", "transmit file (sender)")
	flag.StringVar(&outputFilename, "o", "", "output file (receiver)")
	flag.StringVar(&verbose, "v", "", "verbose output (from v to vvv)")
	flag.Parse()

	if (transmitFilename == "") == (outputFilename == "") {
		fmt.Println("Exactly one of -t or -o needs to be specified")
		os.Exit(1)
	}

	// Setup logger
	h := log.CallerFileHandler(log.StdoutHandler)
	if verbose == "vv" {
		log.Root().SetHandler(log.LvlFilterHandler(log.LvlDebug, h))
	} else if verbose == "v" {
		log.Root().SetHandler(log.LvlFilterHandler(log.LvlInfo, h))
	} else {
		log.Root().SetHandler(log.LvlFilterHandler(log.LvlError, h))
	}

	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return err
	}
	if iface.Flags&net.FlagUp == 0 {
		return errors.New("Interface is not up")
	}

	var sciondConn sciond.Connector
	if localAddr == "" || transmitFilename != "" { // connect to sciond only if needed
		sciondConn, err = sciond.NewService(sciond.DefaultSCIONDAddress).Connect(context.Background())
		if err != nil {
			return err
		}
	}

	var local *snet.UDPAddr
	if localAddr == "" {
		local, err = guessLocalAddress(sciondConn, iface, local)
		if err != nil {
			return err
		}
	} else {
		local, err = snet.ParseUDPAddr(localAddr)
		if err != nil {
			return err
		}

		err = checkAssignedIP(iface, local.Host.IP)
		if err != nil {
			return err
		}
	}

	if local.Host.Port == 0 {
		local.Host.Port = defaultUDP4Port
		fmt.Printf("Binding to default port %d\n", defaultUDP4Port)
	}

	xdpMode := getXDPMode(mode)

	if transmitFilename != "" {
		remote, err := snet.ParseUDPAddr(remoteAddr)
		if err != nil {
			return err
		}
		return mainTx(transmitFilename, &sciondConn, local, remote, iface, queue, maxRateLimit, enablePCC, xdpMode, dumpInterval)
	}
	return mainRx(outputFilename, local, iface, queue, xdpMode, dumpInterval)
}

func mainTx(filename string, sciondConn *sciond.Connector, src, dst *snet.UDPAddr, iface *net.Interface, queue int, maxRateLimit int, enablePCC bool, xdpMode int, dumpInterval time.Duration) (err error) {
	querier, err := initPathResolver(sciondConn, src.IA)
	if err != nil {
		return err
	}

	dst.NextHop, dst.Path, err = resolvePath(querier, src, dst)
	if err != nil {
		fmt.Println("Unable to resolve SCION path.")
		return err
	}
	path, err := prepareSCIONPacketHeader(src, dst, iface)
	if err != nil {
		return err
	}

	herculesInit(iface, src, queue)
	go statsDumper(true, dumpInterval)
	go cleanupOnSignal()
	stats := herculesTx(filename, *path, maxRateLimit, enablePCC, xdpMode)
	printSummary(stats)
	return nil
	//ticker := time.NewTicker(500 * time.Millisecond)
	//go func() {
	//	for t := range ticker.C {
	//		// ... fetch scion paths ...
	//		for path := range paths {
	//			headers = append(headers, prepareSCIONPacketHeader(path ...))
	//		}
	//		hercules_set_paths(headers)
	//	}
	//}()
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

func herculesTx(filename string, path HerculesPath, maxRateLimit int, enablePCC bool, xdpMode int) herculesStats {
	filenamec := C.CString(filename)
	defer C.free(unsafe.Pointer(filenamec))
	p := C.struct_hercules_path{}
	toCPath(path, &p)
	return C.hercules_tx(filenamec, &p, C.int(maxRateLimit), C.bool(enablePCC), C.int(xdpMode))
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

func guessLocalAddress(sciondConn sciond.Connector, iface *net.Interface, local *snet.UDPAddr) (*snet.UDPAddr, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ia, err := sciondConn.LocalIA(ctx)
	if err != nil {
		return nil, err
	}

	ip, err := getLocalIPOnInterface(iface)
	if err != nil {
		return nil, err
	}

	local = &snet.UDPAddr{
		IA:   ia,
		Host: &net.UDPAddr{IP: ip},
	}
	return local, nil
}

func getLocalIPOnInterface(iface *net.Interface) (to4 net.IP, err error) {
	interfaceAddrs, err :=iface.Addrs()
	if err != nil {
		return nil, err
	}
	for _, addr := range interfaceAddrs {
		ip, ok := addr.(*net.IPNet)
		if ok && ip.IP.To4() != nil {
			return ip.IP.To4(), nil
		}
	}
	return nil, errors.New(fmt.Sprintf("Could not find an IPv4 address on interface %s", iface.Name))
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

// XXX scion utils
// Replace with using scion-apps/lib!?
func initPathResolver(sciondConn *sciond.Connector, ia addr.IA) (*sciond.Querier, error) {
	querier := sciond.Querier{
		Connector: *sciondConn,
		IA: ia,
	}
	return &querier, nil
}

func resolvePath(querier *sciond.Querier, src, dst *snet.UDPAddr) (*net.UDPAddr, *spath.Path, error) {

	if src.IA.Equal(dst.IA) {
		hop := net.UDPAddr{
			IP: dst.Host.IP,
			Port: overlay.EndhostPort,
		}
		return &hop, nil, nil
	}
	return resolveRemotePath(querier, dst.IA)
}

func resolveRemotePath(querier *sciond.Querier, dstIA addr.IA) (*net.UDPAddr, *spath.Path, error) {
	ctx, cancelF := context.WithTimeout(context.Background(), 5*time.Second)
	paths, err := querier.Query(ctx, dstIA)
	cancelF()
	if err != nil {
		return nil, nil, err
	}
	if len(paths) == 0 {
		return nil, nil, errors.New("No paths to destination found")
	}

	path := paths[0]
	return path.OverlayNextHop(), path.Path(), nil
}
