package main

import (
	"github.com/google/gopacket/pcap"
	"net"
)

type arpMessage struct {
	handle *pcap.Handle
	ifaceAddr net.HardwareAddr
}
