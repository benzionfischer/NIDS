package rules

import (
	. "awesomeProject/model"
)

// Rule is an interface representing a detection rule.
type Rule interface {
	Detect(packet *Packet) []*Incident
}
