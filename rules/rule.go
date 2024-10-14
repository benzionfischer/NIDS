package rules

import (
	. "awesomeProject/model"
	"net"
)

// Rule is an interface representing a detection rule.
type Rule interface {
	Detect(packet *Packet) (isDetected bool, incidentType IncidentType, ip net.IP)
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
