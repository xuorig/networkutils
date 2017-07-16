package strategies

import (
	"fmt"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// ARP takes care of handling ARP frames
// And displays info to users.
type ARP struct {
	handle *pcap.Handle
}

// Handle ..
func (strategy ARP) Handle(packet gopacket.Packet) {
	arpLayer := packet.Layer(layers.LayerTypeARP)
	if arpLayer != nil {
		arp := arpLayer.(*layers.ARP)
		if arp.Operation == layers.ARPRequest {
			log.Printf("Who has %v? Tell %v", net.IP(arp.DstProtAddress), net.IP(arp.SourceProtAddress))
		} else if arp.Operation == layers.ARPReply {
			log.Printf("%v is at %v", net.IP(arp.SourceProtAddress), net.HardwareAddr(arp.SourceHwAddress))
		} else {
			fmt.Println("ARP Other")
		}
	}
}
