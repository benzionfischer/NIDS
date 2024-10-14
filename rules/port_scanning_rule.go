package rules

import (
	. "awesomeProject/data_structures"
	. "awesomeProject/model"
	"net"
	"time"
)

// ConnectionAttempt struct to hold port and timestamp
type ConnectionAttempt struct {
	Port      string
	Timestamp time.Time
}

// PortScanningRule implements a rule to detect port scanning.
type PortScanningRule struct {
	ConnectionAttempts map[string]map[string][]ConnectionAttempt // Key: Source IP, Destination IP, Value: slice of ConnectionAttempts
	PortScanningDS     PortScanningDS                            // Data structure
}

// NewPortScanningRule creates a new instance of PortScanningRule.
func NewPortScanningRule(threshold int, windowDuration time.Duration) *PortScanningRule {
	return &PortScanningRule{
		ConnectionAttempts: make(map[string]map[string][]ConnectionAttempt),
		PortScanningDS:     NewPortScanningDS(windowDuration, threshold),
	}
}

// Detect checks for port scanning attempts.
func (rule *PortScanningRule) Detect(packet *Packet) (isDetected bool, incidentType IncidentType, ip net.IP) {

	srcIP := packet.SrcIP.String()
	dstIP := packet.DstIP.String()
	dstPort := packet.DstPort
	timestamp := packet.Timestamp

	// Save the record
	rule.PortScanningDS.Save(srcIP, dstIP, dstPort, timestamp)

	// Check if the number of attempts exceeds the threshold
	if rule.PortScanningDS.HasMoreThanXeventsInSlidingWindow(srcIP, dstIP, dstPort) {
		return true, PortScanning, packet.SrcIP // Port scanning detected
	}

	return false, -1, nil // No port scanning detected
}
