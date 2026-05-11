//go:build linux

package app

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type capabilityStatus struct {
	Name string
	OK   bool
	Err  error
}

func effectiveCapabilityStatuses() []capabilityStatus {
	caps, err := readEffectiveCaps()
	return []capabilityStatus{
		{Name: "CAP_NET_RAW", OK: caps&(1<<13) != 0, Err: err},
		{Name: "CAP_NET_ADMIN", OK: caps&(1<<12) != 0, Err: err},
	}
}

func readEffectiveCaps() (uint64, error) {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return 0, fmt.Errorf("invalid CapEff line %q", line)
		}
		return strconv.ParseUint(fields[1], 16, 64)
	}
	return 0, fmt.Errorf("CapEff not found")
}
