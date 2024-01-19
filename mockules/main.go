package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/snet"
	"io"
	"log"
	"math"
	"math/rand"
	"os"
	"time"
)

const (
	blockSize = 1500 - 200
)

func main() {
	var (
		localAddr      string
		remoteAddr     string
		filename       string
		blocks         uint
		lossPercentage float64
	)
	flag.StringVar(&remoteAddr, "d", "", "destination host")
	flag.StringVar(&localAddr, "l", "", "local address")
	flag.StringVar(&filename, "f", "", "filename")
	flag.UintVar(&blocks, "b", 0, "blocks to send before interactive mode")
	flag.Float64Var(&lossPercentage, "p", 0.0, "Simulated packet loss percentage")
	flag.Parse()

	if localAddr == "" {
		log.Fatalln("local address -l is required")
	}
	if remoteAddr == "" {
		log.Fatalln("destination -d is required")
	}
	if filename == "" {
		log.Fatalln("filename -f is required")
	}
	if lossPercentage < 0.0 || lossPercentage > 100.0 {
		log.Fatalln("loss percentage should be in [0, 100]%")
	}

	err := rbudpTxMain(localAddr, remoteAddr, filename, blocks, float32(lossPercentage/100.0))
	if err != nil {
		log.Fatalln(err)
	}
}

func rbudpTxMain(srcAddr, dstAddr, filename string, blocks uint, loss float32) error {
	src, err := snet.ParseUDPAddr(srcAddr)
	if err != nil {
		return err
	}
	dst, err := snet.ParseUDPAddr(dstAddr)
	if err != nil {
		return err
	}

	network := newNetwork()
	querier := newPathQuerier()

	if !dst.IA.Equal(src.IA) {
		ctx, cancelF := context.WithTimeout(context.Background(), 5*time.Second)
		paths, err := querier.Query(ctx, dst.IA)
		cancelF()
		if err != nil {
			return err
		}
		if len(paths) == 0 {
			return errors.New("No paths to destination found")
		}

		path := paths[0]
		log.Printf("Using path:\n\t%s", path)
		dst.Path = path.Dataplane()
		dst.NextHop = path.UnderlayNextHop()
	}

	conn, err := network.Dial(context.Background(), "udp", src.Host, dst, addr.SvcNone)
	if err != nil {
		return err
	}
	defer conn.Close()

	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return err
	}
	fileSize := fileInfo.Size()
	numBlocks := uint32((fileSize + blockSize - 1) / blockSize)

	log.Println("Send startup")
	err = rbudpSendInitial(*conn, fileSize, blockSize)
	if err != nil {
		return err
	}
	log.Println("Wait for ACK..")
	err = rbudpRecvAck(*conn)
	if err != nil {
		return err
	}

	nacks := make(chan uint32, numBlocks)
	ack := make(chan interface{}, 1)
	go rbudpRecvNacks(*conn, nacks, ack)

	log.Println("Send file, first round")
	reader := bufio.NewReader(os.Stdin)
	for i := uint32(0); i < numBlocks; i++ {
		err = rbudpSendBlock(*conn, file, i, loss)
		if err != nil {
			return err
		}
		if blocks != 0 && i > uint32(blocks) {
			log.Printf("Sent chunk %d\n", i)
			reader.ReadString('\n')
		}
	}

	log.Println("Start processing NACKS")
	// XXX: this looks like the protocol should have an explicit ACK.
	numNacks := 0
	for {
		select {
		case i := <-nacks:
			numNacks++
			err = rbudpSendBlock(*conn, file, i, loss)
			if err != nil {
				return err
			}
		case <-ack:
			log.Println("Done (ACK). Num NACKs:", numNacks)
			return nil
		case <-time.After(1 * time.Second):
			log.Println("Done (timeout). Num NACKs:", numNacks)
			return nil
		}
	}
}

func rbudpSendInitial(conn snet.Conn, fileSize int64, blockSize uint32) error {
	buf := make([]byte, blockSize+4)
	binary.LittleEndian.PutUint32(buf, math.MaxUint32)
	binary.LittleEndian.PutUint64(buf[4:], uint64(fileSize))
	binary.LittleEndian.PutUint32(buf[12:], blockSize)
	// Always send full size frames, padded with 0s // XXX don't need to do this here...
	_, err := conn.WriteTo(buf, conn.RemoteAddr()) // XXX: WTF? Write() says ErrNoAddr
	if err != nil {
		return err
	}
	return nil
}

func rbudpSendBlock(conn snet.Conn, file *os.File, i uint32, loss float32) error {
	buf := make([]byte, blockSize+4)
	binary.LittleEndian.PutUint32(buf, i)
	n, err := file.ReadAt(buf[4:], int64(i)*blockSize)
	if err != nil && err != io.EOF {
		return fmt.Errorf("Error reading from file: %v", err)
	}
	// Always send full size frames; pad with 0s
	for p := n + 4; p < len(buf); p++ {
		buf[p] = 0
	}
	if loss >= 0.0 && rand.Float32() < loss {
		return nil
	}
	_, err = conn.WriteTo(buf, conn.RemoteAddr()) // XXX: WTF? Write() says ErrNoAddr
	if err != nil {
		return err
	}
	return nil
}

func rbudpRecvAck(conn snet.Conn) error {
	buf := make([]byte, 2048)
	for { // XXX timeout
		n, addr, err := conn.ReadFrom(buf)
		pkt := buf[:n]
		if err != nil {
			log.Fatal(err)
		}

		// XXX duplicate code
		rest := pkt
		marker := binary.LittleEndian.Uint32(rest)
		rest = rest[4:]
		fmt.Println("NACK: ", addr)
		if marker == math.MaxUint32 {
			count := binary.LittleEndian.Uint32(rest)
			if count == 0 {
				return nil
			}
		}
	}
}

func rbudpRecvNacks(conn snet.Conn, nacks chan uint32, ack chan interface{}) {

	buf := make([]byte, 2048)
	for {
		n, addr, err := conn.ReadFrom(buf)
		pkt := buf[:n]
		if err != nil {
			log.Fatal(err)
		}

		rest := pkt
		marker := binary.LittleEndian.Uint32(rest)
		rest = rest[4:]
		fmt.Println("NACK: ", addr)
		if marker == math.MaxUint32 {
			count := binary.LittleEndian.Uint32(rest)
			if count == 0 {
				ack <- nil
			}
			rest = rest[4:]
			fmt.Println("count:", count)
			for c := uint32(0); c < count; c++ {
				i := binary.LittleEndian.Uint32(rest)
				rest = rest[4:]
				if i>>31 != 0 {
					n := binary.LittleEndian.Uint32(rest)
					rest = rest[4:]
					c++
					first := i & (math.MaxUint32 >> 1)
					last := n & (math.MaxUint32 >> 1)
					fmt.Println(" ", first, "-", last)
					for x := first; x <= last; x++ {
						nacks <- x
					}
				} else {
					fmt.Println(" ", i)
					nacks <- i
				}
			}
		}
	}
}
