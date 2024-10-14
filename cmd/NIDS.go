package cmd

import (
	. "awesomeProject/alert_system"
	. "awesomeProject/loggers"
	. "awesomeProject/model"
	. "awesomeProject/rules"
	"fmt"
)

// NIDS is the main class responsible for managing the detection system.
type NIDS struct {
	PacketSniffer *PacketSniffer
	Rules         []Rule
	Logger        *IncidentLogger
	AlertSystem   *AlertSystem
}

// NewNIDS creates a new instance of the NIDS system with its dependencies.
func NewNIDS(sniffer *PacketSniffer, rules []Rule, logger *IncidentLogger, alertSystem *AlertSystem) *NIDS {
	return &NIDS{
		PacketSniffer: sniffer,
		Rules:         rules,
		Logger:        logger,
		AlertSystem:   alertSystem,
	}
}

// Start begins capturing packets and processing them concurrently.
func (n *NIDS) Start() {
	packetChan := make(chan *Packet, 100) // limit the number of go routines

	// push packets to the channel
	go func() {
		n.PacketSniffer.Capture(packetChan)
	}()

	// for each packet create go routine
	for packet := range packetChan {
		go n.ProcessPacket(packet)
	}
}

// ProcessPacket processes each captured packet.
func (n *NIDS) ProcessPacket(packet *Packet) {
	for _, rule := range n.Rules {
		incidents := rule.Detect(packet)

		// can return a list without incidents
		for _, incident := range incidents {
			n.Logger.LogIncident(incident)
			n.AlertSystem.Notify(fmt.Sprintf("Incident detected at %s from IP %s with type: %s", packet.Timestamp, incident.IP, incident.Type))
		}
	}
}
