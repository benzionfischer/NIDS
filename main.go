package main

import (
	. "awesomeProject/alert_system"
	. "awesomeProject/cmd"
	. "awesomeProject/loggers"
	. "awesomeProject/rules"
	"fmt"
	"os"
	"time"
)

func main() {
	logFile, err := os.OpenFile("incidents.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		fmt.Println("Error opening log file:", err)
		return
	}
	defer logFile.Close()

	packetSniffer, err := NewPacketSniffer("en0") // Change this to your network interface
	if err != nil {
		fmt.Println("Error initializing packet sniffer:", err)
		return
	}

	nids := NewNIDS(packetSniffer,
		[]Rule{
			NewPortScanningRule(10, 30*time.Second),
			NewDDoSRule(15, 30*time.Second),
			NewLargeVolumeRule(10, 30*time.Second), // Adjust thresholds as needed
		},
		&IncidentLogger{LogFile: logFile},
		&AlertSystem{})

	nids.Start() // Start the NIDS
}
