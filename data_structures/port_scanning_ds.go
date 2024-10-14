package data_structures

import (
	"sync"
	"time"
)

// PortScanningDS is a thread-safe data structure to hold timestamps.
type PortScanningDS struct {
	mu sync.Mutex // Mutex to protect access
	// Nested maps: source IP -> destination IP -> destination port -> slice of timestamps
	data      map[string]map[string]map[string][]time.Time
	window    time.Duration
	threshold int
}

// NewPortScanningDS creates a new instance of TimeStampStore.
func NewPortScanningDS(window time.Duration, threshold int) PortScanningDS {
	return PortScanningDS{
		data:      make(map[string]map[string]map[string][]time.Time),
		window:    window,
		threshold: threshold,
	}
}

// Save adds a timestamp for the given source IP, destination IP, and destination port.
func (store *PortScanningDS) Save(srcIP, dstIP, dstPort string, t time.Time) {
	store.mu.Lock() // Lock for writing
	defer store.mu.Unlock()

	// Initialize nested maps if necessary
	if store.data[srcIP] == nil {
		store.data[srcIP] = make(map[string]map[string][]time.Time)
	}
	if store.data[srcIP][dstIP] == nil {
		store.data[srcIP][dstIP] = make(map[string][]time.Time)
	}
	if store.data[srcIP][dstIP][dstPort] == nil {
		store.data[srcIP][dstIP][dstPort] = make([]time.Time, 0)
	}

	// Append the timestamp
	store.data[srcIP][dstIP][dstPort] = append(store.data[srcIP][dstIP][dstPort], t)
}

// HasMoreThanXeventsInSlidingWindow retrieves and deletes timestamps for the given source IP, destination IP, and destination port that are older than the specified window.
func (store *PortScanningDS) HasMoreThanXeventsInSlidingWindow(srcIP, dstIP, dstPort string) bool {
	store.mu.Lock() // Lock for writing
	defer store.mu.Unlock()

	// Get the current time
	now := time.Now()

	// Get the list of timestamps
	timestamps := store.data[srcIP][dstIP][dstPort]

	// Filter out timestamps that are within the time window
	var filtered []time.Time
	for _, t := range timestamps {
		if now.Sub(t) < store.window {
			filtered = append(filtered, t)
		}
	}

	// Update the data structure to only keep timestamps within the window
	store.data[srcIP][dstIP][dstPort] = filtered // Assign filtered timestamps back to the map

	// Return the filtered timestamps
	return len(filtered) > store.threshold
}
