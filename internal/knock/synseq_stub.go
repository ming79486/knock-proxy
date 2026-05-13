//go:build !linux && !windows

package knock

import "context"

func SendSYNSequence(ctx context.Context, opts SendOptions) error { return ErrUnsupported }
func ListenSYNSequence(ctx context.Context, opts ListenOptions, handler Handler) error {
	return ErrUnsupported
}
