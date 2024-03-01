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

// #cgo CFLAGS: -O1 -Wall -DNDEBUG -D_GNU_SOURCE
// #cgo LDFLAGS: ${SRCDIR}/bpf/src/libbpf.a -lm -lelf -pthread -lz
// #pragma GCC diagnostic ignored "-Wunused-variable"
// #include "hercules.h"
// #include <linux/if_xdp.h>
// #include <stdint.h>
// #include <stdlib.h>
// #include <string.h>
import "C"
import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	log "github.com/inconshreveable/log15"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/private/topology"
	"github.com/vishvananda/netlink"
)

type CPathManagement struct {
	numPathsPerDst    []C.int
	maxNumPathsPerDst C.int
	pathsPerDest      []C.struct_hercules_path
}

type layerWithOpts struct {
	Layer gopacket.SerializableLayer
	Opts  gopacket.SerializeOptions
}

type HerculesSession struct {
	session *C.struct_hercules_session
}

type pathStats struct {
	statsBuffer *C.struct_path_stats
}

const XDP_ZEROCOPY = C.XDP_ZEROCOPY
const XDP_COPY = C.XDP_COPY
const minFrameSize = int(C.HERCULES_MAX_HEADERLEN) + 213 // sizeof(struct rbudp_initial_pkt) + rbudp_headerlen

func herculesInit(interfaces []*net.Interface, local *snet.UDPAddr, queue int, MTU int) *HerculesSession {
	var ifIndices []int
	for _, iface := range interfaces {
		ifIndices = append(ifIndices, iface.Index)
	}
	ifacesC := toCIntArray(ifIndices)
	herculesSession := &HerculesSession{
		session: C.hercules_init(&ifacesC[0], C.int(len(interfaces)), toCAddr(local), C.int(queue), C.int(MTU)),
	}
	return herculesSession
}

func herculesTx(session *HerculesSession, filename string, offset int, length int, destinations []*Destination,
	pm *PathManager, maxRateLimit int, enablePCC bool, xdpMode int, numThreads int) herculesStats {
	cFilename := C.CString(filename)
	defer C.free(unsafe.Pointer(cFilename))

	cDests := make([]C.struct_hercules_app_addr, len(destinations))
	for d, dest := range destinations {
		cDests[d] = toCAddr(dest.hostAddr)
	}
	return herculesStatsFromC(C.hercules_tx(
		session.session,
		cFilename,
		C.int(offset),
		C.int(length),
		&cDests[0],
		&pm.cStruct.pathsPerDest[0],
		C.int(len(destinations)),
		&pm.cStruct.numPathsPerDst[0],
		pm.cStruct.maxNumPathsPerDst,
		C.int(maxRateLimit),
		C.bool(enablePCC),
		C.int(xdpMode),
		C.int(numThreads),
	), nil)
}

func herculesRx(session *HerculesSession, filename string, xdpMode int, numThreads int, configureQueues bool, acceptTimeout int, isPCCBenchmark bool) herculesStats {
	cFilename := C.CString(filename)
	defer C.free(unsafe.Pointer(cFilename))
	return herculesStatsFromC(
		C.hercules_rx(session.session, cFilename, C.int(xdpMode), C.bool(configureQueues), C.int(acceptTimeout), C.int(numThreads), C.bool(isPCCBenchmark)),
		nil,
	)
}

func herculesClose(session *HerculesSession) {
	C.hercules_close(session.session)
}

func makePerPathStatsBuffer(numPaths int) *pathStats {
	return &pathStats{
		statsBuffer: C.make_path_stats_buffer(C.int(numPaths)),
	}
}

func herculesGetStats(session *HerculesSession, pStats *pathStats) herculesStats {
	var statsBuffer *C.struct_path_stats = nil
	if pStats != nil {
		statsBuffer = pStats.statsBuffer
	}
	return herculesStatsFromC(C.hercules_get_stats(session.session, statsBuffer), pStats)
}

func herculesStatsFromC(stats C.struct_hercules_stats, pStats *pathStats) herculesStats {
	var ppStats []perPathStats
	if pStats != nil {
		numPaths := int(pStats.statsBuffer.num_paths)
		ppStats = make([]perPathStats, numPaths, numPaths)
		// circumvent Go range checking and pStats.statsBuffer.paths as dynamic struct member
		statsBuffer := (*[1 << 30]C.struct_path_stats_path)(unsafe.Pointer(&pStats.statsBuffer.paths[0]))[:numPaths:numPaths]
		for i := 0; i < numPaths; i++ {
			ppStats[i].pps_target = int64(statsBuffer[i].pps_target)
			ppStats[i].total_packets = int64(statsBuffer[i].total_packets)
		}
	}
	return herculesStats{
		startTime:       uint64(stats.start_time),
		endTime:         uint64(stats.end_time),
		now:             uint64(stats.now),
		txNpkts:         uint64(stats.tx_npkts),
		rxNpkts:         uint64(stats.rx_npkts),
		filesize:        uint64(stats.filesize),
		frameLen:        uint32(stats.framelen),
		chunkLen:        uint32(stats.chunklen),
		totalChunks:     uint32(stats.total_chunks),
		completedChunks: uint32(stats.completed_chunks),
		rateLimit:       uint32(stats.rate_limit),
		paths:           ppStats,
	}
}

func (cpm *CPathManagement) initialize(numDestinations int, numPathsPerDestination int) {
	cpm.numPathsPerDst = make([]C.int, numDestinations)
	cpm.maxNumPathsPerDst = C.int(numPathsPerDestination)
	cpm.pathsPerDest = make([]C.struct_hercules_path, numDestinations*numPathsPerDestination)
}

// HerculesGetReplyPath creates a reply path header for the packet header in headerPtr with given length.
// Returns 0 iff successful.
// This function is exported to C and called to obtain a reply path to send NACKs from the receiver (slow path).
//
//export HerculesGetReplyPath
func HerculesGetReplyPath(headerPtr unsafe.Pointer, length C.int, replyPathStruct *C.struct_hercules_path) C.int {
	buf := C.GoBytes(headerPtr, length)
	replyPath, err := getReplyPathHeader(buf)
	if err != nil {
		log.Debug("HerculesGetReplyPath", "err", err)
		return 1
	}
	// the interface index is handled C-internally
	toCPath(nil, replyPath, replyPathStruct, false, false)
	return 0
}

func getReplyPathHeader(buf []byte) (*HerculesPathHeader, error) {
	packet := gopacket.NewPacket(buf, layers.LayerTypeEthernet, gopacket.Default)
	if err := packet.ErrorLayer(); err != nil {
		return nil, fmt.Errorf("error decoding some part of the packet: %v", err)
	}
	eth := packet.Layer(layers.LayerTypeEthernet)
	if eth == nil {
		return nil, errors.New("error decoding ETH layer")
	}
	dstMAC, srcMAC := eth.(*layers.Ethernet).SrcMAC, eth.(*layers.Ethernet).DstMAC

	ip4 := packet.Layer(layers.LayerTypeIPv4)
	if ip4 == nil {
		return nil, errors.New("error decoding IPv4 layer")
	}
	dstIP, srcIP := ip4.(*layers.IPv4).SrcIP, ip4.(*layers.IPv4).DstIP

	udp := packet.Layer(layers.LayerTypeUDP)
	if udp == nil {
		return nil, errors.New("error decoding IPv4/UDP layer")
	}
	udpPayload := udp.(*layers.UDP).Payload
	udpDstPort := udp.(*layers.UDP).SrcPort

	if len(udpPayload) < 8 { // Guard against bug in ParseScnPkt
		return nil, errors.New("error decoding SCION packet: payload too small")
	}

	sourcePkt := snet.Packet{
		Bytes: udpPayload,
	}
	if err := sourcePkt.Decode(); err != nil {
		return nil, fmt.Errorf("error decoding SCION packet: %v", err)
	}

	rpath, ok := sourcePkt.Path.(snet.RawPath)
	if !ok {
		return nil, fmt.Errorf("error decoding SCION packet: unexpected dataplane path type")
	}
	if len(rpath.Raw) != 0 {
		replyPath, err := snet.DefaultReplyPather{}.ReplyPath(rpath)
		if err != nil {
			return nil, fmt.Errorf("failed to reverse SCION path: %v", err)
		}
		sourcePkt.Path = replyPath
	}

	udpPkt, ok := sourcePkt.Payload.(snet.UDPPayload)
	if !ok {
		return nil, errors.New("error decoding SCION/UDP")
	}

	underlayHeader, err := prepareUnderlayPacketHeader(srcMAC, dstMAC, srcIP, dstIP, uint16(udpDstPort))
	if err != nil {
		return nil, err
	}

	payload := snet.UDPPayload{
		SrcPort: udpPkt.DstPort,
		DstPort: udpPkt.SrcPort,
		Payload: nil,
	}

	destPkt := &snet.Packet{
		PacketInfo: snet.PacketInfo{
			Destination: sourcePkt.Source,
			Source:      sourcePkt.Destination,
			Path:        sourcePkt.Path,
			Payload:     payload,
		},
	}

	if err = destPkt.Serialize(); err != nil {
		return nil, err
	}
	scionHeaderLen := len(destPkt.Bytes)
	payloadLen := etherLen - len(underlayHeader) - scionHeaderLen
	payload.Payload = make([]byte, payloadLen)
	destPkt.Payload = payload

	if err = destPkt.Serialize(); err != nil {
		return nil, err
	}
	scionHeader := destPkt.Bytes[:scionHeaderLen]
	scionChecksum := binary.BigEndian.Uint16(scionHeader[scionHeaderLen-2:])
	headerBuf := append(underlayHeader, scionHeader...)
	herculesPath := HerculesPathHeader{
		Header:          headerBuf,
		PartialChecksum: scionChecksum,
	}
	return &herculesPath, nil
}

// Assumes that the path header memory has already been set up; call allocateCPathHeaderMemory before, if needed
func toCPath(iface *net.Interface, from *HerculesPathHeader, to *C.struct_hercules_path, replaced, enabled bool) {
	headerLen := len(from.Header)
	if len(from.Header) > C.HERCULES_MAX_HEADERLEN {
		panic(fmt.Sprintf("Header too long (%d), can't invoke hercules C API.", len(from.Header)))
	}
	// XXX(matzf): is there a nicer way to do this?
	C.memcpy(unsafe.Pointer(&to.header.header),
		unsafe.Pointer(&from.Header[0]),
		C.ulong(len(from.Header)))
	to.header.checksum = C.ushort(from.PartialChecksum)
	to.headerlen = C.int(headerLen)
	to.payloadlen = C.int(etherLen - headerLen) // TODO(matzf): take actual MTU into account, also when building header
	to.framelen = C.int(etherLen)               // TODO(matzf): "
	if iface != nil {
		to.ifid = C.int(iface.Index)
	}
	to.replaced = C.atomic_bool(replaced)
	to.enabled = C.atomic_bool(enabled)
}

func toCAddr(addr *snet.UDPAddr) C.struct_hercules_app_addr {
	out := C.struct_hercules_app_addr{}
	bufIA := toCIA(addr.IA)
	bufIP := addr.Host.IP.To4()
	bufPort := make([]byte, 2)
	binary.BigEndian.PutUint16(bufPort, uint16(addr.Host.Port))

	C.memcpy(unsafe.Pointer(&out.ia), unsafe.Pointer(&bufIA), C.sizeof_ia)
	C.memcpy(unsafe.Pointer(&out.ip), unsafe.Pointer(&bufIP[0]), 4)
	C.memcpy(unsafe.Pointer(&out.port), unsafe.Pointer(&bufPort[0]), 2)
	return out
}

func toCIA(in addr.IA) C.ia {
	var out C.ia
	bufIA := make([]byte, 8)
	binary.BigEndian.PutUint64(bufIA, uint64(in))
	C.memcpy(unsafe.Pointer(&out), unsafe.Pointer(&bufIA[0]), 8)
	return out
}

func toCIntArray(in []int) []C.int {
	out := make([]C.int, 0, len(in))
	for _, i := range in {
		out = append(out, C.int(i))
	}
	return out
}

func prepareSCIONPacketHeader(src, dst *snet.UDPAddr, iface *net.Interface) (*HerculesPathHeader, error) {
	dstMAC, srcMAC, err := getAddrs(iface, dst.NextHop.IP)
	if err != nil {
		return nil, err
	}

	underlayHeader, err := prepareUnderlayPacketHeader(srcMAC, dstMAC, src.Host.IP, dst.NextHop.IP, uint16(dst.NextHop.Port))
	if err != nil {
		return nil, err
	}

	payload := snet.UDPPayload{
		SrcPort: uint16(src.Host.Port),
		DstPort: uint16(dst.Host.Port),
		Payload: nil,
	}

	dstHostIP, ok := netip.AddrFromSlice(dst.Host.IP)
	if !ok {
		return nil, errors.New("invalid dst host IP")
	}
	srcHostIP, ok := netip.AddrFromSlice(src.Host.IP)
	if !ok {
		return nil, errors.New("invalid src host IP")
	}
	scionPkt := &snet.Packet{
		PacketInfo: snet.PacketInfo{
			Destination: snet.SCIONAddress{IA: dst.IA, Host: addr.HostIP(dstHostIP)},
			Source:      snet.SCIONAddress{IA: src.IA, Host: addr.HostIP(srcHostIP)},
			Path:        dst.Path,
			Payload:     payload,
		},
	}
	if err := scionPkt.Serialize(); err != nil {
		return nil, err
	}
	scionHeaderLen := len(scionPkt.Bytes)
	payloadLen := etherLen - len(underlayHeader) - scionHeaderLen
	payload.Payload = make([]byte, payloadLen)
	scionPkt.Payload = payload
	if err := scionPkt.Serialize(); err != nil {
		return nil, err
	}

	scionHeader := scionPkt.Bytes[:scionHeaderLen]
	scionChecksum := binary.BigEndian.Uint16(scionHeader[scionHeaderLen-2:])
	buf := append(underlayHeader, scionHeader...)
	herculesPath := HerculesPathHeader{
		Header:          buf,
		PartialChecksum: scionChecksum,
	}
	return &herculesPath, nil
}

func prepareUnderlayPacketHeader(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, dstPort uint16) ([]byte, error) {
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
	err := serializeLayersWOpts(buf,
		layerWithOpts{&eth, serializeOpts},
		layerWithOpts{&ip, serializeOptsChecked},
		layerWithOpts{&udp, serializeOpts})
	if err != nil {
		return nil, err
	}

	// return only the header
	return buf.Bytes()[:ethHeader+ipHeader+udpHeader], nil
}

func serializeLayersWOpts(w gopacket.SerializeBuffer, layersWOpts ...layerWithOpts) error {
	err := w.Clear()
	if err != nil {
		return err
	}
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
		err = errors.New("no route found to destination on specified interface")
	}

	dstIP := destination
	if route.Gw != nil {
		dstIP = route.Gw
	}
	dstMAC, err = getNeighborMAC(n, iface.Index, dstIP)
	if err != nil {
		if err.Error() == "missing ARP entry" {
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
	return nil, errors.New("missing ARP entry")
}

func sendICMP(iface *net.Interface, srcIP net.IP, dstIP net.IP) (err error) {
	icmp := layers.ICMPv4{
		TypeCode: layers.ICMPv4TypeEchoRequest,
	}
	buf := gopacket.NewSerializeBuffer()
	serializeOpts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err = gopacket.SerializeLayers(buf, serializeOpts, &icmp)
	if err != nil {
		return err
	}

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

// TODO rewrite path pushing: prepare in Go buffers then have a single call where C fetches them
func (pm *PathManager) pushPaths(session *HerculesSession) {
	C.acquire_path_lock()
	defer C.free_path_lock()
	syncTime := time.Now()

	// prepare and copy header to C
	for d, dst := range pm.dsts {
		if pm.syncTime.After(dst.modifyTime) {
			continue
		}

		dst.pushPaths(d, d*pm.numPathSlotsPerDst)
	}

	pm.syncTime = syncTime
	//C.push_hercules_tx_paths(herculesSession.session) not needed atm
}

// TODO move back to pathstodestination.go
func (ptd *PathsToDestination) pushPaths(pwdIdx, firstSlot int) {
	n := 0
	slot := 0
	if ptd.paths == nil {
		for _, iface := range ptd.pm.interfaces {
			ptd.canSendLocally = ptd.pushPath(&PathMeta{updated: true, enabled: true, iface: iface}, firstSlot)
		}
	} else {
		for p := range ptd.paths {
			path := &ptd.paths[p]
			if path.updated || path.enabled {
				n = slot
			}
			if !ptd.pushPath(path, firstSlot+slot) {
				path.enabled = false
			}
			slot += 1
			path.updated = false
		}
	}
	ptd.pm.cStruct.numPathsPerDst[pwdIdx] = C.int(n + 1)
}

// TODO move back to pathstodestination.go
func (ptd *PathsToDestination) pushPath(path *PathMeta, slot int) bool {
	if path.updated {
		herculesPath, err := ptd.preparePath(path)
		if err != nil {
			log.Error(err.Error() + " - path disabled")
			ptd.pm.cStruct.pathsPerDest[slot].enabled = false
			return false
		}
		toCPath(path.iface, herculesPath, &ptd.pm.cStruct.pathsPerDest[slot], true, path.enabled)
	} else {
		ptd.pm.cStruct.pathsPerDest[slot].enabled = C.atomic_bool(path.enabled)
	}
	return true
}
