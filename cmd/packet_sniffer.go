package cmd

import (
	. "awesomeProject/model"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"net"
)

// PacketSniffer handles the logic of capturing network packets.
type PacketSniffer struct {
	handle *pcap.Handle
}

// NewPacketSniffer initializes the packet sniffer and returns an error if it fails.
func NewPacketSniffer(device string) (*PacketSniffer, error) {
	handle, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("error opening device %s: %v", device, err)
	}
	return &PacketSniffer{handle: handle}, nil
}

// Capture captures a packet and returns a Packet struct or an error if it fails.
func (sniffer *PacketSniffer) Capture() (*Packet, error) {
	packetSource := gopacket.NewPacketSource(sniffer.handle, sniffer.handle.LinkType())
	for packet := range packetSource.Packets() {
		// Extracting the IP layer and handling the case where it might be nil
		ipLayer := packet.NetworkLayer()
		if ipLayer == nil {
			continue // Skip packets without an IP layer
		}

		srcIP := ipLayer.NetworkFlow().Src().String()
		dstIP := ipLayer.NetworkFlow().Dst().String()

		// Check for the transport layer (TCP or UDP)
		transportLayer := packet.TransportLayer()
		if transportLayer == nil {
			continue // Skip packets without a transport layer
		}

		// Handle TCP specifically; if you want to handle UDP, you can add similar logic
		transportFlow := transportLayer.TransportFlow()
		if &transportFlow == nil {
			continue // Skip non-TCP packets, or handle UDP as needed
		}

		// Extract source and destination ports
		srcPort := transportFlow.Src().String()
		dstPort := transportFlow.Dst().String()

		// Return a new Packet struct with the relevant data
		return &Packet{
			Timestamp: packet.Metadata().Timestamp,
			SrcIP:     net.ParseIP(srcIP),
			SrcPort:   srcPort,
			DstIP:     net.ParseIP(dstIP),
			DstPort:   dstPort,
			Length:    len(packet.Data()),
		}, nil
	}
	return nil, fmt.Errorf("no packets captured")
}

// Close releases the resources held by the packet sniffer.
func (sniffer *PacketSniffer) Close() {
	sniffer.handle.Close()
}
