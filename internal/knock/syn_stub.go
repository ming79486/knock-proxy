//go:build !linux && !windows

package knock

import (
	"context"
	"errors"
)

func Send(ctx context.Context, opts SendOptions) error {
	return ErrUnsupported
}

func Listen(ctx context.Context, opts ListenOptions, handler Handler) error {
	return ErrUnsupported
}

func ListenUDPPassive(ctx context.Context, opts ListenOptions, handler Handler) error {
	return ErrUnsupported
}

func CheckServerPrivileges() error {
	return errors.New("server requires Linux CAP_NET_ADMIN and CAP_NET_RAW, or must be run as root")
}
