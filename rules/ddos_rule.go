package rules

import (
	. "awesomeProject/model"
	"awesomeProject/utils"
	"net"
	"sync"
	"time"
)

// DDoSRule implements a rule to detect DDoS attempts.
type DDoSRule struct {
	RequestLog     map[string][]time.Time // Key: Source IP, Value: Slice of timestamps for each request
	Threshold      int                    // Maximum allowed requests from a single IP within the time window
	WindowDuration time.Duration          // Time window for counting requests
	mu             sync.Mutex             // Mutex to ensure thread-safe access to RequestLog
}

// NewDDoSRule creates a new instance of DDoSRule.
func NewDDoSRule(threshold int, windowDuration time.Duration) *DDoSRule {
	return &DDoSRule{
		RequestLog:     make(map[string][]time.Time),
		Threshold:      threshold,
		WindowDuration: windowDuration,
	}
}

// Detect checks for potential DDoS attempts.
func (rule *DDoSRule) Detect(packet *Packet) (isDetected bool, incidentType IncidentType, ip net.IP) {

	srcIP := packet.SrcIP.String()
	now := time.Now()

	// Get the list of request timestamps for this IP
	requests := rule.RequestLog[srcIP]

	// Add the current request timestamp
	requests = append(requests, packet.Timestamp)

	// Filter out requests that are older than the window duration
	requests = utils.Filter[time.Time](requests, func(timestamp time.Time) bool {
		return now.Sub(timestamp) < rule.WindowDuration
	})

	// Update the map with the filtered and updated request log
	rule.RequestLog[srcIP] = requests

	// Check if the number of requests exceeds the threshold
	if len(requests) > rule.Threshold {
		return true, DDoSAttack, packet.SrcIP // DDoS attempt detected
	}

	return false, -1, nil // No DDoS attempt detected
}
