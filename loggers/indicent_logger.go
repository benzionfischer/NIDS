package loggers

import (
	. "awesomeProject/model"
	"encoding/json"
	"fmt"
	"os"
)

// IncidentLogger handles logging of detected incidents.
type IncidentLogger struct {
	LogFile *os.File
}

func (logger *IncidentLogger) LogIncident(incident *Incident) {
	logData, _ := json.Marshal(incident)
	fmt.Fprintln(logger.LogFile, string(logData)) // Log to file
}
