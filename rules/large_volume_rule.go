package rules

import (
	. "awesomeProject/model"
	"awesomeProject/utils"
	"net"
	"sync"
	"time"
)

// DataTransfer represents a record of data transfer for an IP.
type DataTransfer struct {
	Volume    int       // Data volume in bytes
	Timestamp time.Time // Time of the data transfer
}

// LargeVolumeRule implements a rule to detect large data transfers.
type LargeVolumeRule struct {
	DataLog        map[string][]DataTransfer // Key: Source IP, Value: Slice of data transfers (volume and timestamp)
	Threshold      int                       // Maximum allowed data volume (in bytes) within the time window
	WindowDuration time.Duration             // Time window for counting data volume
	mu             sync.Mutex                // Mutex to make access to DataLog thread-safe
}

// NewLargeVolumeRule creates a new instance of LargeVolumeRule.
func NewLargeVolumeRule(threshold int, windowDuration time.Duration) *LargeVolumeRule {
	return &LargeVolumeRule{
		DataLog:        make(map[string][]DataTransfer),
		Threshold:      threshold,
		WindowDuration: windowDuration,
	}
}

// Detect checks for large data transfer attempts.
func (rule *LargeVolumeRule) Detect(packet *Packet) (isDetected bool, incidentType IncidentType, ip net.IP) {

	srcIP := packet.SrcIP.String()
	now := time.Now()

	// Lock the mutex to ensure thread-safe access to the DataLog map
	rule.mu.Lock()

	// Get the list of data transfers for this IP
	transfers := rule.DataLog[srcIP]
	if transfers == nil {
		transfers = make([]DataTransfer, 0)
	}

	// Add the current data volume (assumed from packet size) to the list
	transfers = append(transfers, DataTransfer{
		Volume:    packet.Length, // assuming packet.Length gives you the data size in bytes
		Timestamp: now,
	})

	// Filter out transfers that are older than the window duration
	transfers = utils.Filter[DataTransfer](transfers, func(transfer DataTransfer) bool {
		return now.Sub(transfer.Timestamp) < rule.WindowDuration
	})

	// Update the map with the filtered and updated data log
	rule.DataLog[srcIP] = transfers

	// Calculate the total data volume within the window
	totalVolume := 0
	for _, transfer := range transfers {
		totalVolume += transfer.Volume
	}

	// Unlock the mutex after modifications are done
	rule.mu.Unlock()

	// Check if the total data volume exceeds the threshold
	if totalVolume > rule.Threshold {
		return true, LargeVolumeTraffic, packet.SrcIP // Large data transfer detected
	}

	return false, -1, nil // No large data transfer detected
}
