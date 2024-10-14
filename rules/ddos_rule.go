package rules

import (
	. "awesomeProject/model"
	"awesomeProject/utils"
	"net"
	"sync"
	"time"
)

// DDoSRule detects potential DDoS attempts based on request frequency.
type DDoSRule struct {
	sync.Mutex                            // Ensures thread-safe access to RequestLog
	RequestLog     map[string][]time.Time // Logs requests per Source IP
	Threshold      int                    // Max allowed requests per IP within the time window
	WindowDuration time.Duration          // Time window for evaluating requests
}

// NewDDoSRule initializes a new DDoSRule with the given threshold and window duration.
func NewDDoSRule(threshold int, windowDuration time.Duration) *DDoSRule {
	return &DDoSRule{
		RequestLog:     make(map[string][]time.Time),
		Threshold:      threshold,
		WindowDuration: windowDuration,
	}
}

// Detect analyzes packets to detect potential DDoS attempts.
// Returns a flag indicating if an attack is detected, the incident type, and the source IP.
func (rule *DDoSRule) Detect(packet *Packet) (bool, IncidentType, net.IP) {
	rule.Lock()
	defer rule.Unlock()

	srcIP := packet.SrcIP.String()
	now := time.Now()

	// Retrieve the request log for the source IP, initializing if necessary
	requests := rule.getRequestLog(srcIP)

	// Clean up old requests outside the window duration
	requests = rule.cleanOldRequests(requests, now)

	// Add the new request timestamp
	requests = append(requests, packet.Timestamp)

	// Update the request log for this IP
	rule.RequestLog[srcIP] = requests

	// Detect if the request count exceeds the threshold
	if len(requests) > rule.Threshold {
		return true, DDoSAttack, packet.SrcIP
	}

	return false, -1, nil
}

// getRequestLog retrieves or initializes the request log for a given source IP.
func (rule *DDoSRule) getRequestLog(srcIP string) []time.Time {
	if requests, exists := rule.RequestLog[srcIP]; exists {
		return requests
	}
	return []time.Time{}
}

// cleanOldRequests filters out requests older than the allowed window duration.
func (rule *DDoSRule) cleanOldRequests(requests []time.Time, now time.Time) []time.Time {
	return utils.Filter(requests, func(timestamp time.Time) bool {
		return now.Sub(timestamp) < rule.WindowDuration
	})
}
