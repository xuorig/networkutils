package main

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var (
	// Network device / adapter
	device = "lo0"
	// Promiscuous mode
	promiscuous       = false
	snapshotLen int32 = 1024
	err         error
	timeout     time.Duration = -time.Millisecond * 10
	handle      *pcap.Handle
	buffer      gopacket.SerializeBuffer
	options     gopacket.SerializeOptions
)

func main() {
	// Open pcap device
	handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	err = handle.SetBPFFilter("tcp and port 8080")
	if err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		fmt.Print(packet.Dump())
	}
}
