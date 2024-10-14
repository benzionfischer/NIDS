package rules

import (
	. "awesomeProject/model"
	"awesomeProject/utils"
	"sync"
	"time"
)

// ConnectionAttempt holds information about a port and the timestamp of an attempt.
type ConnectionAttempt struct {
	Port      string
	Timestamp time.Time
}

// PortScanningRule implements logic to detect port scanning behavior.
type PortScanningRule struct {
	sync.Mutex
	ConnectionAttempts map[string]map[string][]ConnectionAttempt // Tracks attempts per Source IP -> Destination IP
	Threshold          int                                       // Maximum allowed attempts within the time window
	WindowDuration     time.Duration                             // Time window for counting attempts
}

// NewPortScanningRule initializes a new PortScanningRule instance.
func NewPortScanningRule(threshold int, windowDuration time.Duration) *PortScanningRule {
	return &PortScanningRule{
		ConnectionAttempts: make(map[string]map[string][]ConnectionAttempt),
		Threshold:          threshold,
		WindowDuration:     windowDuration,
	}
}

// Detect checks if the incoming packet triggers a port scanning detection.
// Returns detection status, incident type, and the IP involved.
func (rule *PortScanningRule) Detect(packet *Packet) []*Incident {
	rule.Lock()
	defer rule.Unlock()

	srcIP := packet.SrcIP.String()
	dstIP := packet.DstIP.String()
	now := time.Now()

	// Initialize or retrieve connection attempts for the given srcIP -> dstIP
	attempts := rule.getConnectionAttempts(srcIP, dstIP)

	// Clean old connection attempts outside the window
	attempts = rule.cleanOldAttempts(attempts, now)

	// Update or add the current connection attempt for the destination port
	attempts = rule.updateAttempt(attempts, packet.DstPort, packet.Timestamp)

	// Save the updated attempts back to the map
	rule.ConnectionAttempts[srcIP][dstIP] = attempts

	// Check if the number of attempts exceeds the threshold
	if len(attempts) > rule.Threshold {
		return []*Incident{NewIncident(packet.SrcIP, PortScanning, packet.Timestamp)}
	}

	return []*Incident{}
}

// getConnectionAttempts retrieves or initializes the slice of ConnectionAttempts for a given srcIP -> dstIP.
func (rule *PortScanningRule) getConnectionAttempts(srcIP, dstIP string) []ConnectionAttempt {
	// If there's no record for this source IP, initialize it
	if _, exists := rule.ConnectionAttempts[srcIP]; !exists {
		rule.ConnectionAttempts[srcIP] = make(map[string][]ConnectionAttempt)
	}

	// Retrieve the list of attempts for this srcIP -> dstIP, or initialize it if it doesn't exist
	if attempts, exists := rule.ConnectionAttempts[srcIP][dstIP]; exists {
		return attempts
	}
	return []ConnectionAttempt{}
}

// cleanOldAttempts filters out connection attempts older than the allowed window duration.
func (rule *PortScanningRule) cleanOldAttempts(attempts []ConnectionAttempt, now time.Time) []ConnectionAttempt {
	return utils.Filter(attempts, func(attempt ConnectionAttempt) bool {
		return now.Sub(attempt.Timestamp) < rule.WindowDuration
	})
}

// updateAttempt updates the timestamp for an existing port attempt or adds a new one.
func (rule *PortScanningRule) updateAttempt(attempts []ConnectionAttempt, port string, timestamp time.Time) []ConnectionAttempt {
	// Check if an attempt for the same port already exists
	isExists, existingAttempt := utils.Find(attempts, func(attempt ConnectionAttempt) bool {
		return attempt.Port == port
	})

	// Update the timestamp of the existing attempt or add a new one
	if isExists {
		existingAttempt.Timestamp = utils.MaxTime(existingAttempt.Timestamp, timestamp)
	} else {
		attempts = append(attempts, ConnectionAttempt{Port: port, Timestamp: timestamp})
	}

	return attempts
}
