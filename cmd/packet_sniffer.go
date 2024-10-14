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
		return nil, fmt.Errorf("error opening device %s: %w", device, err)
	}
	return &PacketSniffer{handle: handle}, nil
}

// Capture captures packets and sends them to a channel for processing.
func (sniffer *PacketSniffer) Capture(packetChan chan<- *Packet) {
	packetSource := gopacket.NewPacketSource(sniffer.handle, sniffer.handle.LinkType())
	for packet := range packetSource.Packets() {

		// To process packets synchronously (not using goroutines), you can do:
		if convertedPacket := sniffer.convertToPacketDTO(packet); convertedPacket != nil {
			packetChan <- convertedPacket
		}

		// To process packet asynchronously (by go routines), you can do:
		//go func(p gopacket.Packet) {
		//	if convertedPacket := sniffer.convertToPacketDTO(p); convertedPacket != nil {
		//		packetChan <- convertedPacket
		//	}
		//}(packet) // Pass the current packet to the goroutine
	}
}

// convertToPacketDTO converts a gopacket.Packet to our Packet DTO or returns nil if it should be ignored.
func (sniffer *PacketSniffer) convertToPacketDTO(packet gopacket.Packet) *Packet {
	ipLayer := packet.NetworkLayer()
	if ipLayer == nil {
		return nil // Skip packets without an IP layer
	}

	srcIP, dstIP := ipLayer.NetworkFlow().Src().String(), ipLayer.NetworkFlow().Dst().String()
	transportLayer := packet.TransportLayer()
	if transportLayer == nil {
		return nil // Skip packets without a transport layer
	}

	srcPort, dstPort := transportLayer.TransportFlow().Src().String(), transportLayer.TransportFlow().Dst().String()

	return &Packet{
		Timestamp: packet.Metadata().Timestamp,
		SrcIP:     net.ParseIP(srcIP),
		SrcPort:   srcPort,
		DstIP:     net.ParseIP(dstIP),
		DstPort:   dstPort,
		Length:    len(packet.Data()),
	}
}

//// Close releases the resources held by the packet sniffer.
//func (sniffer *PacketSniffer) Close() {
//	if err := sniffer.handle.Close(); err != nil {
//		fmt.Printf("Error closing pcap handle: %v\n", err)
//	}
//}
