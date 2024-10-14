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

// NewPacketSniffer initializes packet sniffer.
func NewPacketSniffer(device string) (*PacketSniffer, error) {
	handle, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	return &PacketSniffer{handle: handle}, nil
}

// Capture captures a packet and returns a Packet struct.
func (sniffer *PacketSniffer) Capture() (*Packet, error) {
	packetSource := gopacket.NewPacketSource(sniffer.handle, sniffer.handle.LinkType())
	for packet := range packetSource.Packets() {
		ipLayer := packet.NetworkLayer()
		if ipLayer != nil {
			// Get the source and destination IPs directly
			srcIP := ipLayer.NetworkFlow().Src().String()
			dstIP := ipLayer.NetworkFlow().Dst().String()

			// Check for the transport layer (TCP or UDP)
			transportLayer := packet.TransportLayer()
			if transportLayer == nil {
				continue
			}

			tcp := transportLayer.TransportFlow()
			srcPort := tcp.Src().String()
			dstPort := tcp.Dst().String()

			return &Packet{
				Timestamp: packet.Metadata().Timestamp,
				SrcIP:     net.ParseIP(srcIP),
				SrcPort:   srcPort,
				DstIP:     net.ParseIP(dstIP),
				DstPort:   dstPort,
				Length:    len(packet.Data()),
			}, nil
		}
	}
	return nil, fmt.Errorf("no packets captured")
}
