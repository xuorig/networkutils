package strategies

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// Strategy ...
type Strategy interface {
	Handle(packet gopacket.Packet)
}

// NewStrategy xxx
func NewStrategy(handle *pcap.Handle, strategy string) Strategy {
	if strategy == "arp" {
		return &ARP{handle}
	} else if strategy == "arp-poison" {
		return &ARPPoison{handle}
	}

	// TODO: Handle default to all
	return &ARP{handle}
}
