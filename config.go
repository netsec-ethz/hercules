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
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/snet"
)

type HerculesGeneralConfig struct {
	Direction    string
	DumpInterval time.Duration
	Interface    string
	Mode         string
	MTU          int
	Queue        int
	NumThreads   int
	Verbosity    string
	LocalAddress string
}

type SiteConfig struct {
	HostAddr string
	NumPaths int
	PathSpec []PathSpec
}

type HerculesReceiverConfig struct {
	HerculesGeneralConfig
	OutputFile      string
	ConfigureQueues bool
	AcceptTimeout   int
}

type HerculesSenderConfig struct {
	HerculesGeneralConfig
	TransmitFile    string
	FileOffset      int
	FileLength      int
	EnablePCC       bool
	RateLimit       int
	NumPathsPerDest int
	Destinations    []SiteConfig
}

var (
	localAddrRegexp             = regexp.MustCompile(`^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):([0-9]{1,5})$`)
	configurableInterfaceRegexp = regexp.MustCompile(`^[a-zA-Z0-9]+$`)
)

// receiver related

func (config *HerculesReceiverConfig) initializeDefaults() {
	config.HerculesGeneralConfig.initializeDefaults()
	config.OutputFile = ""
	config.ConfigureQueues = false
	config.AcceptTimeout = 0
}

// Validates configuration parameters that have been provided, does not validate for presence of mandatory arguments.
func (config *HerculesReceiverConfig) validateLoose() error {
	if config.Direction != "" && config.Direction != "download" {
		return errors.New("field Direction must either be empty or 'download'")
	}
	if err := config.HerculesGeneralConfig.validateLoose(); err != nil {
		return err
	}

	// check if output file exists (or folder)
	if config.OutputFile != "" {
		if stat, err := os.Stat(config.OutputFile); err != nil {
			if !os.IsNotExist(err) {
				return err
			}
		} else if stat.IsDir() {
			return fmt.Errorf("output file %s is a directory", config.OutputFile)
		} else {
			log.Info(fmt.Sprintf("output file %s exists: will be overwritten", config.OutputFile))
		}
		dir := filepath.Dir(config.OutputFile)
		stat, err := os.Stat(dir)
		if err != nil {
			return err
		}
		if !stat.IsDir() {
			return fmt.Errorf("not a directory: %s", dir)
		}
	}

	if config.ConfigureQueues {
		if !configurableInterfaceRegexp.MatchString(config.Interface) {
			return fmt.Errorf("cannot configure interface '%s' - escaping not implemented", config.Interface)
		}
	}
	return nil
}

// Validates all configuration parameters, also checks presence of mandatory parameters.
func (config *HerculesReceiverConfig) validateStrict() error {
	if err := config.HerculesGeneralConfig.validateStrict(); err != nil {
		return err
	}
	if err := config.validateLoose(); err != nil {
		return err
	}

	if config.OutputFile == "" {
		return errors.New("no output file specified")
	}
	return nil
}

// Merge commandline arguments into the current configuration.
func (config *HerculesReceiverConfig) mergeFlags(flags *Flags) error {
	if err := forbidFlags([]string{"pcc", "p", "d", "t", "np", "be", "resv"}, "receiving"); err != nil {
		return err
	}
	if err := config.HerculesGeneralConfig.mergeFlags(flags); err != nil {
		return nil
	}
	if isFlagPassed("o") {
		config.OutputFile = flags.outputFilename
	}
	if isFlagPassed("timeout") {
		config.AcceptTimeout = flags.acceptTimeout
	}
	return nil
}

// sender related

func (config *HerculesSenderConfig) initializeDefaults() {
	config.HerculesGeneralConfig.initializeDefaults()
	config.TransmitFile = ""
	config.FileOffset = -1 // no offset
	config.FileLength = -1 // use the whole file
	config.EnablePCC = true
	config.RateLimit = 3333333
	config.NumPathsPerDest = 1
	config.Destinations = nil
}

// Validates configuration parameters that have been provided, does not validate for presence of mandatory arguments.
func (config *HerculesSenderConfig) validateLoose() error {
	if config.Direction != "" && config.Direction != "upload" {
		return errors.New("field Direction must either be empty or 'upload'")
	}
	if err := config.HerculesGeneralConfig.validateLoose(); err != nil {
		return err
	}

	// check that the file exists
	if config.TransmitFile != "" {
		stat, err := os.Stat(config.TransmitFile)
		if err != nil {
			return err
		}
		if stat.IsDir() {
			return errors.New("file to transmit is a directory")
		}
	}

	if config.FileOffset > 0 && config.FileLength < 0 {
		return errors.New("must provide a valid file length")
	}

	if config.RateLimit < 100 {
		log.Warn(fmt.Sprintf("rate limit is really low (%d packets per second)", config.RateLimit))
	}

	if config.NumPathsPerDest > maxPathsPerReceiver {
		return fmt.Errorf("can use at most %d paths per destination; configured limit (%d) too large", maxPathsPerReceiver, config.NumPathsPerDest)
	}

	// validate destinations
	for d, _ := range config.Destinations {
		if config.Destinations[d].NumPaths > maxPathsPerReceiver {
			return fmt.Errorf("can use at most %d paths per destination; max for destination %d is too large (%d)", maxPathsPerReceiver, d, config.Destinations[d].NumPaths)
		}

		udpAddress, err := snet.ParseUDPAddr(config.Destinations[d].HostAddr)
		if err != nil {
			return err
		}
		if udpAddress.Host.Port == 0 {
			return errors.New("must specify a destination port")
		}
		if (udpAddress.IA == addr.IA{}) {
			return errors.New("must provide IA for destination address")
		}
	}
	return nil
}

// Validates all configuration parameters and checks the presence of mandatory parameters
func (config *HerculesSenderConfig) validateStrict() error {
	if err := config.HerculesGeneralConfig.validateStrict(); err != nil {
		return err
	}
	if err := config.validateLoose(); err != nil {
		return err
	}

	if config.TransmitFile == "" {
		return errors.New("you must specify a file to send")
	}

	if len(config.Destinations) == 0 {
		return errors.New("you must specify at least one destination")
	}
	return nil
}

// Merge commandline arguments into the current configuration.
func (config *HerculesSenderConfig) mergeFlags(flags *Flags) error {
	if err := forbidFlags([]string{"o", "timeout"}, "sending"); err != nil {
		return err
	}
	if err := config.HerculesGeneralConfig.mergeFlags(flags); err != nil {
		return nil
	}
	if isFlagPassed("pcc") {
		config.EnablePCC = flags.enablePCC
	}
	if isFlagPassed("p") {
		config.RateLimit = flags.maxRateLimit
	}
	if isFlagPassed("d") {
		sites := make([]SiteConfig, 0)
		for _, remoteAddr := range flags.remoteAddrs {
			sites = append(sites, SiteConfig{
				HostAddr: remoteAddr,
			})
		}
		config.Destinations = sites
	}
	if isFlagPassed("t") {
		config.TransmitFile = flags.transmitFilename
	}
	if isFlagPassed("foffset") {
		config.FileOffset = flags.fileOffset
	}
	if isFlagPassed(("flength")) {
		config.FileLength = flags.fileLength
	}
	if isFlagPassed("np") {
		config.NumPathsPerDest = flags.numPaths
	}
	return nil
}

// Converts config.Destinations into []*Destination for use by herculesTx.
// Assumes config (strictly) is valid.
func (config *HerculesSenderConfig) destinations() []*Destination {
	var dests []*Destination
	for d, dst := range config.Destinations {
		// since config is valid, there can be no error
		hostAddr, _ := snet.ParseUDPAddr(dst.HostAddr)
		dest := &Destination{
			hostAddr: hostAddr,
			pathSpec: &config.Destinations[d].PathSpec,
			numPaths: config.NumPathsPerDest,
		}
		if config.Destinations[d].NumPaths > 0 {
			dest.numPaths = config.Destinations[d].NumPaths
		}
		dests = append(dests, dest)
	}
	return dests
}

// helpers

func (config *HerculesGeneralConfig) initializeDefaults() {
	config.Direction = ""
	config.DumpInterval = 1 * time.Second
	config.Interface = ""
	config.Mode = ""
	config.MTU = 1500
	config.NumThreads = 1
	config.Queue = 0
	config.Verbosity = ""
	config.LocalAddress = ""
}

func (config *HerculesGeneralConfig) validateLoose() error {
	var iface *net.Interface
	if config.Direction != "" && config.Direction != "upload" && config.Direction != "download" {
		return errors.New("field Direction must either be 'upload', 'download' or empty")
	}
	if config.DumpInterval <= 0 {
		return errors.New("field DumpInterval must be strictly positive")
	}
	if config.Interface != "" {
		var err error
		iface, err = net.InterfaceByName(config.Interface)
		if err != nil {
			return err
		}
		if iface.Flags&net.FlagUp == 0 {
			return errors.New("interface is not up")
		}
	}
	if config.Mode != "z" && config.Mode != "c" && config.Mode != "" {
		return fmt.Errorf("unknown mode %s", config.Mode)
	}

	// check LocalAddress
	if config.LocalAddress != "" {
		udpAddress, err := snet.ParseUDPAddr(config.LocalAddress)
		if err != nil {
			return err
		}
		if udpAddress.Host.Port == 0 {
			return errors.New("must specify a source port")
		}
		if (udpAddress.IA == addr.IA{}) {
			return errors.New("must provide IA for local address")
		}
		if iface != nil {
			if err := checkAssignedIP(iface, udpAddress.Host.IP); err != nil {
				return err
			}
		}
	}

	if config.MTU < minFrameSize {
		return fmt.Errorf("MTU too small: %d < %d", config.MTU, minFrameSize)
	}
	if config.MTU > 9038 {
		return fmt.Errorf("can not use jumbo frames of size %d > 9038", config.MTU)
	}

	if config.Queue < 0 {
		return errors.New("queue number must be non-negative")
	}

	if config.NumThreads < 1 {
		return errors.New("must at least use 1 worker thread")
	}

	if config.Verbosity != "" && config.Verbosity != "v" && config.Verbosity != "vv" {
		return errors.New("verbosity must be empty or one of 'v', 'vv'")
	}
	return nil
}

// Check that the mandatory general configuration has been set.
//
// WARNING: this function does not validate the contents of the options to avoid duplicate calls to validateLoose(),
// as this function is called within Hercules(Sender|Receiver)Config.validateLoose() already.
func (config *HerculesGeneralConfig) validateStrict() error {
	if config.Interface == "" {
		return errors.New("you must specify a network interface to use")
	}
	if config.LocalAddress == "" {
		return errors.New("you must specify a local address")
	}
	if config.MTU > 8015 {
		log.Warn(fmt.Sprintf("using frame size %d > 8015 (IEEE 802.11)", config.MTU))
	}
	return nil
}

func (config *HerculesGeneralConfig) mergeFlags(flags *Flags) error {
	if isFlagPassed("n") {
		config.DumpInterval = flags.dumpInterval * time.Second
	}
	if isFlagPassed("i") {
		config.Interface = flags.ifname
	}
	if isFlagPassed("m") {
		config.Mode = flags.mode
	}
	if isFlagPassed("l") {
		config.LocalAddress = flags.localAddr
	}
	if isFlagPassed("q") {
		config.Queue = flags.queue
	}
	if isFlagPassed("nt") {
		config.NumThreads = flags.numThreads
	}
	if isFlagPassed("v") {
		config.Verbosity = flags.verbose
	}
	if isFlagPassed("mtu") {
		config.MTU = flags.mtu
	}
	return nil
}

func (config *HerculesGeneralConfig) getXDPMode() (mode int) {
	switch config.Mode {
	case "z":
		mode = XDP_ZEROCOPY
	case "c":
		mode = XDP_COPY
	default:
		mode = 0
	}
	return mode
}

// Checks that none of flags are passed by the command line.
// mode should either be "sending" or "receiving" and is only used in errors
//
// Returns an error if any of the provided flags was passed by the command line, nil otherwise
func forbidFlags(flags []string, mode string) error {
	var illegalFlags []string
	for _, f := range flags {
		if isFlagPassed(f) {
			illegalFlags = append(illegalFlags, f)
		}
	}

	if len(illegalFlags) > 0 {
		return fmt.Errorf("-%s not permitted for %s", strings.Join(illegalFlags, ", -"), mode)
	} else {
		return nil
	}
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
	return fmt.Errorf("interface '%s' does not have the IP address '%s'", iface.Name, localAddr)
}
