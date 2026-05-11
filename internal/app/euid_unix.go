//go:build !windows

package app

import "os"

func geteuid() int {
	return os.Geteuid()
}
