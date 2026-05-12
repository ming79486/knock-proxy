//go:build !linux && !windows

package knock

import "errors"

func CheckClientSupport(method string) error {
	if method != "tcp-syn" {
		return nil
	}
	return errors.New("tcp-syn knock is not implemented on this platform; switch knock.method to udp")
}
