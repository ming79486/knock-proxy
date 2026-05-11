//go:build windows

package app

func geteuid() int {
	return -1
}
