//go:build !linux && !windows

package knock

import "errors"

func CheckClientSupport(method string) error {
	if method != "tcp-syn" {
		return nil
	}
	return errors.New("tcp-syn knock on this platform requires root/BPF or equivalent packet injection support; switch knock.method to udp")
}
