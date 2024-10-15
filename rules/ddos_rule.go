package rules

import (
	. "awesomeProject/model"
	"awesomeProject/utils"
	"fmt"
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

// NewDDoSRule initializes a new DDoSRule with the given threshold and window duration and starts the cleanup job.
func NewDDoSRule(threshold int, windowDuration time.Duration) *DDoSRule {
	rule := &DDoSRule{
		RequestLog:     make(map[string][]time.Time),
		Threshold:      threshold,
		WindowDuration: windowDuration,
	}

	rule.startCleanUpJob() // Start the cleanup job
	return rule
}

// Detect analyzes packets to detect potential DDoS attempts.
// Returns a flag indicating if an attack is detected, the incident type, and the source IP.
func (rule *DDoSRule) Detect(packet *Packet) []*Incident {
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
		return []*Incident{NewIncident(packet.SrcIP, DDoSAttack, packet.Timestamp, packet)}
	}

	return []*Incident{}
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

// cleanUp removes old request logs for all source IPs that fall outside the window duration.
func (rule *DDoSRule) cleanUp() {
	rule.Lock()
	defer rule.Unlock()

	fmt.Print("CleanUp activated for DDoSRule\n")
	now := time.Now()
	for srcIP, requests := range rule.RequestLog {
		// Clean old requests for each IP
		rule.RequestLog[srcIP] = rule.cleanOldRequests(requests, now)

		// If no valid requests remain, delete the IP entry
		if len(rule.RequestLog[srcIP]) == 0 {
			delete(rule.RequestLog, srcIP)
		}
	}
}

// StartCleanUpJob starts a background goroutine that runs the cleanUp function every 30 minutes.
func (rule *DDoSRule) startCleanUpJob() {
	ticker := time.NewTicker(30 * time.Minute) // Ticker triggers every 30 minutes

	go func() {
		for {
			select {
			case <-ticker.C:
				rule.cleanUp() // Call the cleanUp function on every tick
			}
		}
	}()
}
