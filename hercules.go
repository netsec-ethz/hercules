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
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	log "github.com/inconshreveable/log15"
	"github.com/scionproto/scion/pkg/snet"
)

type arrayFlags []string

type Flags struct {
	dumpInterval         time.Duration
	enablePCC            bool
	ifNames              arrayFlags
	localAddr            string
	maxRateLimit         int
	mode                 string
	mtu                  int
	queue                int
	numThreads           int
	remoteAddrs          arrayFlags
	transmitFilename     string
	fileOffset           int
	fileLength           int
	outputFilename       string
	verbose              string
	numPaths             int
	acceptTimeout        int
	perPathStats         string
	expectPaths          int
	pccBenchmarkDuration int
}

const (
	maxPathsPerReceiver int = 255 // the maximum path index needs to fit into a uint8, value 255 is reserved for "don't track"
)

var (
	startupVersion string // Add detailed version information to binary for reproducible tests
	etherLen       int
)

func (i *arrayFlags) String() string {
	return "[\n\t\"" + strings.Join(*i, "\",\n\t\"") + "\"\n]"
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func isFlagPassed(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func main() {
	err := realMain()
	if err != nil {
		fmt.Println(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func realMain() error {
	var (
		configFile     string
		flags          Flags
		senderConfig   HerculesSenderConfig
		receiverConfig HerculesReceiverConfig
		version        bool
	)
	flag.DurationVar(&flags.dumpInterval, "n", time.Second, "Print stats at given interval")
	flag.BoolVar(&flags.enablePCC, "pcc", true, "Enable performance-oriented congestion control (PCC)")
	flag.Var(&flags.ifNames, "i", "interface")
	flag.StringVar(&flags.localAddr, "l", "", "local address")
	flag.IntVar(&flags.maxRateLimit, "p", 3333333, "Maximum allowed send rate in Packets per Second (default: 3'333'333, ~40Gbps)")
	flag.StringVar(&flags.mode, "m", "", "XDP socket bind mode (Zero copy: z; Copy mode: c)")
	flag.IntVar(&flags.queue, "q", 0, "Use queue n")
	flag.IntVar(&flags.numThreads, "nt", 0, "Maximum number of worker threads to use")
	flag.Var(&flags.remoteAddrs, "d", "destination host address(es); omit the ia part of the address to add a receiver IP to the previous destination")
	flag.StringVar(&flags.transmitFilename, "t", "", "transmit file (sender)")
	flag.IntVar(&flags.fileOffset, "foffset", -1, "file offset")
	flag.IntVar(&flags.fileLength, "flength", -1, "file length (needed if you specify an offset)")
	flag.StringVar(&flags.outputFilename, "o", "", "output file (receiver)")
	flag.StringVar(&flags.verbose, "v", "", "verbose output (from '' to vv)")
	flag.IntVar(&flags.numPaths, "np", 1, "Maximum number of different paths per destination to use at the same time")
	flag.StringVar(&configFile, "c", "", "File to parse configuration from, you may overwrite any configuration using command line arguemnts")
	flag.IntVar(&flags.mtu, "mtu", 0, "Set the frame size to use")
	flag.IntVar(&flags.acceptTimeout, "timeout", 0, "Abort accepting connections after this timeout (seconds)")
	flag.BoolVar(&version, "version", false, "Output version and exit")
	flag.StringVar(&flags.perPathStats, "ps", "", "Write per-path statistics to this file (CSV)")
	flag.IntVar(&flags.expectPaths, "ep", 1, "Number of paths to expect for collecting per-path statistics (receiver only)")
	flag.IntVar(&flags.pccBenchmarkDuration, "pccbd", 0, "PCC benchmark duration in (seconds). ")
	flag.Parse()

	if version {
		fmt.Printf("Build version: %s\n", startupVersion)
		os.Exit(0)
	}

	if err := configureLogger(flags.verbose); err != nil {
		return err
	}

	// decide whether to send or to receive based on flags
	sendMode := false
	recvMode := false
	if isFlagPassed("t") {
		sendMode = true
	}
	if isFlagPassed("o") {
		recvMode = true
	}
	if sendMode && recvMode {
		return errors.New("you can not pass -o and -t at the same time")
	}

	// parse config file, if provided
	senderConfig.initializeDefaults()
	receiverConfig.initializeDefaults()
	if isFlagPassed("c") {
		undecoded := make(map[string]struct{})
		if meta, err := toml.DecodeFile(configFile, &senderConfig); err != nil {
			return err
		} else {
			for _, key := range meta.Undecoded() {
				undecoded[strings.Join(key, ".")] = struct{}{}
			}
		}
		if meta, err := toml.DecodeFile(configFile, &receiverConfig); err != nil {
			return err
		} else {
			for _, key := range meta.Undecoded() {
				key := strings.Join(key, ".")
				if _, ok := undecoded[key]; ok {
					log.Warn(fmt.Sprintf("Configuration file contains key \"%s\" which is unknown for both, sending and receiving", key))
				}
			}
		}
	}

	// if not clear yet, decide whether to send or receive based on config file
	if !sendMode && !recvMode {
		if senderConfig.Direction == "upload" {
			sendMode = true
		} else if senderConfig.Direction == "download" {
			recvMode = true
		} else if senderConfig.Direction == "" {
			if senderConfig.TransmitFile != "" {
				sendMode = true
			}
			if receiverConfig.OutputFile != "" {
				recvMode = true
			}
			if sendMode && recvMode {
				return errors.New("unclear whether to send or to receive, use -t or -o on the command line or set Direction in the configuration file")
			}
			if !sendMode && !recvMode {
				return errors.New("unclear whether to send or to receive, use -t or -o on the command line or at least one of Direction, OutputFile and TransmitFile in the configuration file")
			}
		} else {
			return fmt.Errorf("'%s' is not a valid value for Direction", senderConfig.Direction)
		}
	}

	if sendMode {
		if senderConfig.PerPathStatsFile != "" && !senderConfig.EnablePCC {
			return errors.New("in send mode, path stats are currently only available with PCC")
		}
		if err := senderConfig.validateLoose(); err != nil {
			return errors.New("in config file: " + err.Error())
		}
		if err := senderConfig.mergeFlags(&flags); err != nil {
			return errors.New("on command line: " + err.Error())
		}
		if err := configureLogger(senderConfig.Verbosity); err != nil {
			return err
		}
		if err := senderConfig.validateStrict(); err != nil {
			return err
		}
		return mainTx(&senderConfig)
	} else if recvMode {
		if err := receiverConfig.validateLoose(); err != nil {
			return errors.New("in config file: " + err.Error())
		}
		if err := receiverConfig.mergeFlags(&flags); err != nil {
			return errors.New("on command line: " + err.Error())
		}
		if err := configureLogger(receiverConfig.Verbosity); err != nil {
			return err
		}
		if err := receiverConfig.validateStrict(); err != nil {
			return err
		}
		return mainRx(&receiverConfig)
	} else {
		// we should not end up here...
		return errors.New("unclear whether to send or receive")
	}
}

func configureLogger(verbosity string) error {
	// Setup logger
	h := log.CallerFileHandler(log.StdoutHandler)
	if verbosity == "vv" {
		log.Root().SetHandler(log.LvlFilterHandler(log.LvlDebug, h))
	} else if verbosity == "v" {
		log.Root().SetHandler(log.LvlFilterHandler(log.LvlInfo, h))
	} else if verbosity == "" {
		log.Root().SetHandler(log.LvlFilterHandler(log.LvlError, h))
	} else {
		return errors.New("-v can only be vv, v or empty")
	}
	return nil
}

// Assumes config to be strictly valid.
func mainTx(config *HerculesSenderConfig) (err error) {
	// since config is valid, there can be no errors here:
	etherLen = config.MTU
	localAddress, _ := snet.ParseUDPAddr(config.LocalAddress)
	interfaces, _ := config.interfaces()
	destinations := config.destinations()

	pm, err := initNewPathManager(
		interfaces,
		destinations,
		localAddress,
		uint64(config.RateLimit)*uint64(config.MTU))
	if err != nil {
		return err
	}

	pm.choosePaths()
	session := herculesInit(interfaces, localAddress, config.Queue, config.MTU)
	pm.pushPaths(session)
	if !pm.canSendToAllDests() {
		return errors.New("some destinations are unreachable, abort")
	}

	aggregateStats := aggregateStats{}
	done := make(chan struct{}, 1)
	go statsDumper(session, true, config.DumpInterval, &aggregateStats, config.PerPathStatsFile, config.NumPathsPerDest*len(config.Destinations), done, config.PCCBenchMarkDuration)
	go cleanupOnSignal(session)
	stats := herculesTx(session, config.TransmitFile, config.FileOffset, config.FileLength,
		destinations, pm, config.RateLimit, config.EnablePCC, config.getXDPMode(),
		config.NumThreads)
	done <- struct{}{}
	printSummary(stats, aggregateStats)
	<-done // wait for path stats to be flushed
	herculesClose(session)
	return nil
}

// Assumes config to be strictly valid.
func mainRx(config *HerculesReceiverConfig) error {
	// since config is valid, there can be no errors here:
	etherLen = config.MTU
	interfaces, _ := config.interfaces()
	localAddr, _ := snet.ParseUDPAddr(config.LocalAddress)

	isPCCBenchmark := false
	if config.PCCBenchMarkDuration > 0 {
		isPCCBenchmark = true
	}
	session := herculesInit(interfaces, localAddr, config.Queue, config.MTU)
	aggregateStats := aggregateStats{}
	done := make(chan struct{}, 1)
	go statsDumper(session, false, config.DumpInterval, &aggregateStats, config.PerPathStatsFile, config.ExpectNumPaths, done, config.PCCBenchMarkDuration)
	go cleanupOnSignal(session)
	stats := herculesRx(session, config.OutputFile, config.getXDPMode(), config.NumThreads, config.ConfigureQueues,
		config.AcceptTimeout, isPCCBenchmark)
	done <- struct{}{}
	printSummary(stats, aggregateStats)
	<-done // wait for path stats to be flushed
	herculesClose(session)
	return nil
}

func cleanupOnSignal(session *HerculesSession) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, os.Kill)
	// Block until any signal is received.
	<-c
	herculesClose(session)
	os.Exit(128 + 15) // Customary exit code after SIGTERM
}
