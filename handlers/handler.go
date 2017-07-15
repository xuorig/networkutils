package handlers

import "github.com/google/gopacket"

// Handler ...
type Handler interface {
	Handle(packet gopacket.Packet)
}

// NewHandler xxx
func NewHandler(strategy string) Handler {
	if strategy == "arp" {
		return &ARPHandler{}
	}

	// TODO: Handle default to all
	return &ARPHandler{}
}
