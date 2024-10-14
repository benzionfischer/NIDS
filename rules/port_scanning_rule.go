package rules

import (
	. "awesomeProject/model"
	"awesomeProject/utils"
	"net"
	"sync"
	"time"
)

// ConnectionAttempt struct to hold port and timestamp
type ConnectionAttempt struct {
	Port      string
	Timestamp time.Time
}

// PortScanningRule implements a rule to detect port scanning.
type PortScanningRule struct {
	sync.Mutex
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

	// Lock for writing to safely update connection attempts
	rule.Lock()
	defer rule.Unlock()

	// Check if the source IP map exists, if not, initialize it
	if rule.ConnectionAttempts[srcIP] == nil {
		rule.ConnectionAttempts[srcIP] = make(map[string][]ConnectionAttempt)
	}

	// Get the list of attempts for the current srcIP -> dstIP
	if rule.ConnectionAttempts[srcIP][dstIP] == nil {
		rule.ConnectionAttempts[srcIP][dstIP] = make([]ConnectionAttempt, 0)
	}

	attempts := rule.ConnectionAttempts[srcIP][dstIP]

	// Remove old attempts
	attempts = utils.Filter(attempts, func(attempt ConnectionAttempt) bool {
		return now.Sub(attempt.Timestamp) < rule.WindowDuration
	})

	// Find dstPort attempt
	isExists, dstPortAttempt := utils.Find(attempts, func(attempt ConnectionAttempt) bool {
		return attempt.Port == packet.DstPort
	})

	if isExists {
		dstPortAttempt.Timestamp = utils.MaxTime(dstPortAttempt.Timestamp, packet.Timestamp)
	} else {
		attempts = append(attempts, ConnectionAttempt{Port: packet.DstPort, Timestamp: packet.Timestamp})
	}

	// Update the map with the filtered list
	rule.ConnectionAttempts[srcIP][dstIP] = attempts

	// Check if the number of attempts exceeds the threshold
	if len(attempts) > rule.Threshold {
		return true, PortScanning, packet.SrcIP // Port scanning detected
	}

	return false, -1, nil // No port scanning detected
}
