package model

import (
	"net"
	"time"
)

// Packet represents a network packet.
type Packet struct {
	Timestamp time.Time
	SrcIP     net.IP
	SrcPort   string
	DstIP     net.IP
	DstPort   string
	Length    int
	Payload   string
}
