// see: https://github.com/google/gopacket/blob/master/examples/arpscan/arpscan.go
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	FlagLowerUp     = 1 << 16
	arpPingInterval = 5 * time.Second
)

func scanIface(ctx context.Context, wg *sync.WaitGroup, iface net.Interface) {
	defer wg.Done()

	// We just look for IPv4 addresses, so try to find if the interface has one.
	addr := new(net.IPNet)
	addrs, err := iface.Addrs()
	if err != nil {
		log.Printf("ERROR: %s - failed to get NIC addrs: %s\n", iface.Name, err)
		return
	}

	// skip iface without IP
	if len(addrs) == 0 {
		return
	}

	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok {
			if ip4 := ipnet.IP.To4(); ip4 != nil {
				addr = &net.IPNet{
					IP:   ip4,
					Mask: ipnet.Mask[len(ipnet.Mask)-4:],
				}
				break
			}
		}
	}

	// Open up a pcap handle for packet reads/writes.
	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Printf("ERROR: failed to open pcap interface: %s\n", err)
		return
	}
	defer handle.Close()

	// Start up a goroutine to read in packet data.
	log.Println(":: scanning interface -", iface.Name)
	//wg.Add(1)
	go readARP(ctx, wg, handle, &iface)

	ticker := time.NewTicker(arpPingInterval)
	for {
		select {
		case <-ctx.Done():
			ticker.Stop()
			log.Printf(":: [%s] Stop scanner", iface.Name)
			return
		case <-ticker.C:
			// Write our scan packets out to the handle.
			if err := writeARP(ctx, handle, &iface, addr); err != nil {
				log.Printf("ERROR: %s - error writing packets: %v\n", iface.Name, err)
				return
			}
		}
	}
}

// readARP watches a handle for incoming ARP responses we might care about, and prints them.
//
// readARP loops until 'stop' is closed.
func readARP(ctx context.Context, wg *sync.WaitGroup, handle *pcap.Handle, iface *net.Interface) {
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()
	defer wg.Done()

	var packet gopacket.Packet
	for {
		select {
		case <-ctx.Done():
			log.Printf(":: [%s] Stop reader", iface.Name)
			return
		case packet = <-in:
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			arp := arpLayer.(*layers.ARP)
			if arp.Operation != layers.ARPReply || bytes.Equal(iface.HardwareAddr, arp.SourceHwAddress) {
				// This is a packet I sent.
				continue
			}
			// Note:  we might get some packets here that aren't responses to ones we've sent,
			// if for example someone else sends US an ARP request.  Doesn't much matter, though...
			// all information is good information :)
			log.Printf(":: [%s] Found %v (%v)", iface.Name,
				net.IP(arp.SourceProtAddress),
				net.HardwareAddr(arp.SourceHwAddress))
		}
	}
}

// writeARP writes an ARP request for each address on our local network to the
// pcap handle.
func writeARP(ctx context.Context, handle *pcap.Handle, iface *net.Interface, addr *net.IPNet) error {
	// Set up all the layers' fields we can.
	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(iface.HardwareAddr),
		SourceProtAddress: []byte(addr.IP),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
	}
	// Set up buffer and options for serialization.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	// Send one packet for every address.
	for _, ip := range ips(addr) {
		select {
		case <-ctx.Done():
			log.Printf(":: [%s] Stop writer", iface.Name)
			return context.Canceled
		default:
		}

		//log.Printf(":: [%s] Write %s", iface.Name, ip.String())
		arp.DstProtAddress = ip
		if err := gopacket.SerializeLayers(buf, opts, &eth, &arp); err != nil {
			log.Printf(":: WARN - %s\n", err)
		}
		if err := handle.WritePacketData(buf.Bytes()); err != nil {
			return err
		}
	}
	return nil
}

// ips is a simple and not very good method for getting all IPv4 addresses from a
// net.IPNet.  It returns all IPs it can over the channel it sends back, closing
// the channel when done.
func ips(n *net.IPNet) (out []net.IP) {
	num := binary.BigEndian.Uint32([]byte(n.IP))
	mask := binary.BigEndian.Uint32([]byte(n.Mask))
	num &= mask
	for mask < 0xffffffff {
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], num)
		out = append(out, net.IP(buf[:]))
		mask++
		num++
	}
	return
}

func getInterfaces() ([]net.Interface, error) {
	allIfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	ifaces := make([]net.Interface, 0, len(allIfaces))
	for _, iface := range allIfaces {
		if iface.Flags&net.FlagPointToPoint != 0 ||
			iface.Flags&net.FlagLoopback != 0 ||
			iface.Flags&net.FlagUp == 0 {
			// skip tunnels, loopbacks or down interfaces
			continue
		}

		if !isPhysicalNIC(iface) {
			continue
		}
		ifaces = append(ifaces, iface)
	}
	return ifaces, nil
}
