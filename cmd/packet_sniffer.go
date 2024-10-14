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

// Capture captures packets and sends them to a channel for processing.
func (sniffer *PacketSniffer) Capture(packetChan chan<- *Packet) {
	for {
		packetSource := gopacket.NewPacketSource(sniffer.handle, sniffer.handle.LinkType())
		for packet := range packetSource.Packets() {
			ipLayer := packet.NetworkLayer()
			if ipLayer == nil {
				continue
			}

			srcIP := ipLayer.NetworkFlow().Src().String()
			dstIP := ipLayer.NetworkFlow().Dst().String()
			transportLayer := packet.TransportLayer()
			if transportLayer == nil {
				continue
			}

			transportFlow := transportLayer.TransportFlow()
			srcPort := transportFlow.Src().String()
			dstPort := transportFlow.Dst().String()

			packetChan <- &Packet{
				Timestamp: packet.Metadata().Timestamp,
				SrcIP:     net.ParseIP(srcIP),
				SrcPort:   srcPort,
				DstIP:     net.ParseIP(dstIP),
				DstPort:   dstPort,
				Length:    len(packet.Data()),
			}
		}
	}
}

// Close releases the resources held by the packet sniffer.
func (sniffer *PacketSniffer) Close() {
	sniffer.handle.Close()
}
