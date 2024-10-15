package model

import (
	"net"
	"time"
)

// Incident represents a security incident with associated details.
type Incident struct {
	IP        net.IP       // The IP address related to the incident
	Type      IncidentType // The type of incident
	Timestamp time.Time    // The time when the incident occurred
	Attempt   *Packet      // attempt
}

// NewIncident is a constructor for creating a new Incident instance.
func NewIncident(ip net.IP, incidentType IncidentType, timestamp time.Time, attempt *Packet) *Incident {
	return &Incident{
		IP:        ip,
		Type:      incidentType,
		Timestamp: timestamp,
		Attempt:   attempt,
	}
}
