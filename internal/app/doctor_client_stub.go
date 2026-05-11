//go:build !windows

package app

import (
	"fmt"

	"github.com/ming79486/knock-proxy/internal/config"
	"github.com/ming79486/knock-proxy/internal/knock"
)

func printPlatformClientDoctor(rt config.ClientRuntime) {
	if err := knock.CheckClientSupport(rt.KnockMethod); err != nil {
		fmt.Printf("[WARN] %v\n", err)
	} else {
		fmt.Printf("[OK] client knock method available: %s\n", rt.KnockMethod)
	}
}
