package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/xuorig/networkutils/strategies"
)

var strategyToBPFFilter = map[string]string{
	"all": "",
	"arp": "arp",
}

var (
	promiscuous       = false
	snapshotLen int32 = 1024
	err         error
	timeout     time.Duration = -time.Millisecond * 10
	handle      *pcap.Handle
	buffer      gopacket.SerializeBuffer
	options     gopacket.SerializeOptions
)

func main() {
	devicePtr := flag.String("d", "eth0", "Name of the network device.")
	strategyType := flag.String("s", "all", "Packet handling strategy")
	flag.Parse()

	// Open pcap device
	fmt.Println(*devicePtr)
	handle, err = pcap.OpenLive(*devicePtr, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	setBPFFilterFromStrategy(*strategyType, handle)
	strategy := strategies.NewStrategy(handle, *strategyType)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		strategy.Handle(packet)
	}
}

func setBPFFilterFromStrategy(strategy string, handle *pcap.Handle) {
	bpfFilter := strategyToBPFFilter[strategy]
	err = handle.SetBPFFilter(bpfFilter)
	if err != nil {
		log.Fatal(err)
	}
}
