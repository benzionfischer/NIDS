package rules

import (
	. "awesomeProject/model"
	"awesomeProject/utils"
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
	Threshold          int                                       // Maximum attempts allowed within the time window
	WindowDuration     time.Duration                             // Time window for counting attempts
}

// NewPortScanningRule creates a new instance of PortScanningRule.
func NewPortScanningRule(threshold int, windowDuration time.Duration) *PortScanningRule {
	return &PortScanningRule{
		ConnectionAttempts: make(map[string]map[string][]ConnectionAttempt),
		Threshold:          threshold,
		WindowDuration:     windowDuration,
	}
}

// Detect checks for port scanning attempts.
func (rule *PortScanningRule) Detect(packet *Packet) (isDetected bool, incidentType IncidentType, ip net.IP) {

	srcIP := packet.SrcIP.String()
	dstIP := packet.DstIP.String()
	now := time.Now()

	// Check if the source IP map exists, if not, initialize it
	if rule.ConnectionAttempts[srcIP] == nil {
		rule.ConnectionAttempts[srcIP] = make(map[string][]ConnectionAttempt)
	}

	// Get the list of attempts for the current srcIP -> dstIP
	attempts := rule.ConnectionAttempts[srcIP][dstIP]

	// Initialize if nil
	if attempts == nil {
		attempts = make([]ConnectionAttempt, 0)
	}

	// Filter out any existing attempts with the same port as the current packet
	for i := 0; i < len(attempts); i++ {
		if attempts[i].Port == packet.DstPort {
			// Remove the attempt by slicing out the element
			attempts = append(attempts[:i], attempts[i+1:]...)
			i-- // Adjust index to avoid skipping elements after deletion
		}
	}

	// Append the new connection attempt
	attempts = append(attempts, ConnectionAttempt{Port: packet.DstPort, Timestamp: packet.Timestamp})

	// Filter the list of attempts to keep only those within the time window
	attempts = utils.Filter[ConnectionAttempt](attempts, func(attempt ConnectionAttempt) bool {
		return now.Sub(attempt.Timestamp) < rule.WindowDuration
	})

	// Update the map after modifications
	rule.ConnectionAttempts[srcIP][dstIP] = attempts

	// Check if the number of attempts exceeds the threshold
	if len(attempts) > rule.Threshold {
		return true, PortScanning, packet.SrcIP // Port scanning detected
	}

	return false, -1, nil // No port scanning detected
}
