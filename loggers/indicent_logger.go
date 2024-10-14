package loggers

import (
	. "awesomeProject/rules"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"
)

// IncidentLogger handles logging of detected incidents.
type IncidentLogger struct {
	LogFile *os.File
}

func (logger *IncidentLogger) LogIncident(timestamp time.Time, ip net.IP, incidentType IncidentType) {
	incident := map[string]interface{}{
		"timestamp": timestamp,
		"ip":        ip,
		"type":      incidentType.String(),
	}
	logData, _ := json.Marshal(incident)
	fmt.Fprintln(logger.LogFile, string(logData)) // Log to file
}
