//go:build !linux

package app

type capabilityStatus struct {
	Name string
	OK   bool
	Err  error
}

func effectiveCapabilityStatuses() []capabilityStatus {
	return nil
}
