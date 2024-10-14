package rules

import (
	. "awesomeProject/model"
	"awesomeProject/utils"
	"net"
	"sync"
	"time"
)

// DataTransfer represents a record of data transfer for an IP address.
type DataTransfer struct {
	Volume    int       // Data volume in bytes
	Timestamp time.Time // Timestamp of the data transfer
}

// LargeVolumeRule detects large data transfers exceeding a threshold within a specific time window.
type LargeVolumeRule struct {
	DataLog        map[string][]DataTransfer // Records of data transfers, keyed by IP address
	Threshold      int                       // Maximum allowed data volume (in bytes) within the time window
	WindowDuration time.Duration             // Time window within which data volume is counted
	mu             sync.Mutex                // Mutex to ensure thread-safe access to DataLog
}

// NewLargeVolumeRule creates and initializes a new LargeVolumeRule instance.
func NewLargeVolumeRule(threshold int, windowDuration time.Duration) *LargeVolumeRule {
	return &LargeVolumeRule{
		DataLog:        make(map[string][]DataTransfer),
		Threshold:      threshold,
		WindowDuration: windowDuration,
	}
}

// Detect checks if the given packet causes a large data transfer.
// It returns whether the detection is triggered, the type of incident, and the IP involved.
func (rule *LargeVolumeRule) Detect(packet *Packet) (bool, IncidentType, net.IP) {
	rule.mu.Lock()
	defer rule.mu.Unlock()

	// Track data transfers by source IP
	srcIP := packet.SrcIP.String()
	now := time.Now()

	// Fetch or initialize the transfer list for this IP
	transfers := rule.getTransfers(srcIP)

	// Add the current packet's data volume to the transfer list
	transfers = rule.addTransfer(transfers, packet.Length, packet.Timestamp)

	// Remove outdated transfers that are outside the time window
	transfers = rule.cleanOldTransfers(transfers, now)

	// Update the DataLog with the cleaned and updated transfers
	rule.DataLog[srcIP] = transfers

	// Calculate the total data volume for the current window
	totalVolume := rule.calculateTotalVolume(transfers)

	// Check if the total volume exceeds the threshold
	if totalVolume > rule.Threshold {
		return true, LargeVolumeTraffic, packet.SrcIP
	}

	// No large transfer detected
	return false, -1, nil
}

// getTransfers retrieves the list of data transfers for a given IP address.
func (rule *LargeVolumeRule) getTransfers(ip string) []DataTransfer {
	if transfers, exists := rule.DataLog[ip]; exists {
		return transfers
	}
	return []DataTransfer{}
}

// addTransfer appends a new data transfer record to the transfer list.
func (rule *LargeVolumeRule) addTransfer(transfers []DataTransfer, volume int, timestamp time.Time) []DataTransfer {
	return append(transfers, DataTransfer{
		Volume:    volume,
		Timestamp: timestamp,
	})
}

// cleanOldTransfers filters out data transfers that fall outside of the allowed time window.
func (rule *LargeVolumeRule) cleanOldTransfers(transfers []DataTransfer, now time.Time) []DataTransfer {
	return utils.Filter(transfers, func(transfer DataTransfer) bool {
		return now.Sub(transfer.Timestamp) < rule.WindowDuration
	})
}

// calculateTotalVolume computes the total data volume of all valid transfers within the time window.
func (rule *LargeVolumeRule) calculateTotalVolume(transfers []DataTransfer) int {
	totalVolume := 0
	for _, transfer := range transfers {
		totalVolume += transfer.Volume
	}
	return totalVolume
}
