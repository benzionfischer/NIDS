package alert_system

import "fmt"

// AlertSystem notifies users of detected incidents.
type AlertSystem struct {
	// Placeholder for notification channels (e.g., email, SMS)
}

// Notify simulates notifying users of detected incidents.
func (alert *AlertSystem) Notify(incident string) {
	// Implement notification logic (e.g., email, SMS)
	fmt.Println("Alert:", incident)
}
