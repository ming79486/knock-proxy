//go:build !linux

package knock

import "context"

func ListenUDPPassiveSequence(ctx context.Context, opts ListenOptions, handler Handler) error {
	return ErrUnsupported
}
