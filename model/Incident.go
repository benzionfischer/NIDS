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
}

// NewIncident is a constructor for creating a new Incident instance.
func NewIncident(ip net.IP, incidentType IncidentType, timestamp time.Time) *Incident {
	return &Incident{
		IP:        ip,
		Type:      incidentType,
		Timestamp: timestamp,
	}
}

// Incident type enum
type IncidentType int

const (
	PortScanning       IncidentType = iota // 0
	DDoSAttack                             // 1
	LargeVolumeTraffic                     // 2
)

// String method for better readability
func (it IncidentType) String() string {
	switch it {
	case PortScanning:
		return "Port Scanning"
	case DDoSAttack:
		return "DDoS Attack"
	case LargeVolumeTraffic:
		return "Large Volume Traffic"
	default:
		return "Unknown Incident"
	}
}
