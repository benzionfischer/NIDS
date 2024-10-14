package cmd

import (
	. "awesomeProject/alert_system"
	. "awesomeProject/loggers"
	. "awesomeProject/model"
	. "awesomeProject/rules"
	"fmt"
	"time"
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

func (n *NIDS) Start() {
	for {
		packet, err := n.PacketSniffer.Capture()
		if err != nil {
			fmt.Println("Error capturing packet:", err)
			continue
		}
		n.ProcessPacket(packet)
	}
}

func (n *NIDS) ProcessPacket(packet *Packet) {
	for _, rule := range n.Rules {
		isDetected, incidentType, ip := rule.Detect(packet)
		if isDetected {
			n.Logger.LogIncident(time.Now(), ip, incidentType) // Use the srcIP returned from the rule
			n.AlertSystem.Notify(fmt.Sprintf("Incident detected at %s from IP %s with type: %s", packet.Timestamp, ip, incidentType))
			break // Exit after the first rule is triggered
		}
	}
}
