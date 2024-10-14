package model

// Incident type enum
type IncidentType int

const (
	PortScanning       IncidentType = iota // 0
	DDoSAttack                             // 1
	LargeVolumeTraffic                     // 2
	SQLInjection
	CodeExecution
	FileRead
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
	case SQLInjection:
		return "SQL Injection"
	case CodeExecution:
		return "Code Execution"
	case FileRead:
		return "File Read"
	default:
		return "Unknown Incident"
	}
}
