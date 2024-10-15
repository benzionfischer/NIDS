package rules

import (
	. "awesomeProject/model"
	"awesomeProject/utils"
	"fmt"
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
	rule := &PortScanningRule{
		ConnectionAttempts: make(map[string]map[string][]ConnectionAttempt),
		Threshold:          threshold,
		WindowDuration:     windowDuration,
	}

	rule.startCleanUpJob()
	return rule
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

	// Update or add the current connection attempt for the destination port
	attempts = rule.updateAttempt(attempts, packet.DstPort, packet.Timestamp)

	// Clean old connection attempts outside the window
	attempts = rule.cleanOldAttempts(attempts, now)

	// Save the updated attempts back to the map
	rule.ConnectionAttempts[srcIP][dstIP] = attempts

	// Check if the number of attempts exceeds the threshold
	if len(attempts) > rule.Threshold {
		return []*Incident{NewIncident(packet.SrcIP, PortScanning, packet.Timestamp, packet)}
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

// cleanUp removes outdated connection attempts and prunes empty entries from the ConnectionAttempts map.
// It iterates over all source IPs and destination IPs to remove attempts older than the sliding window.
// If no attempts remain for a srcIP->dstIP pair, it deletes the entire entry.
func (rule *PortScanningRule) cleanUp() {
	rule.Lock()
	defer rule.Unlock()

	fmt.Print("CleanUp activated for PortScanningRule\n")

	now := time.Now()

	// Iterate over all source IPs
	for srcIP, dstMap := range rule.ConnectionAttempts {
		// Iterate over all destination IPs for the current source IP
		for dstIP, attempts := range dstMap {
			// Clean up old connection attempts outside the window
			cleanedAttempts := rule.cleanOldAttempts(attempts, now)

			if len(cleanedAttempts) > 0 {
				// If there are valid (non-expired) attempts, update the map
				rule.ConnectionAttempts[srcIP][dstIP] = cleanedAttempts
			} else {
				// If no valid attempts remain, delete the dstIP entry
				delete(rule.ConnectionAttempts[srcIP], dstIP)
			}
		}

		// If no more destination IPs remain for the source IP, delete the srcIP entry
		if len(rule.ConnectionAttempts[srcIP]) == 0 {
			delete(rule.ConnectionAttempts, srcIP)
		}
	}
}

// StartCleanUpJob starts a background goroutine that runs the cleanUp function every 30 minutes.
func (rule *PortScanningRule) startCleanUpJob() {
	ticker := time.NewTicker(30 * time.Minute)

	go func() {
		for {
			select {
			case <-ticker.C:
				rule.cleanUp() // Call the cleanUp function every 30 minutes
			}
		}
	}()
}
