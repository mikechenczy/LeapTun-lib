//go:build !android && !darwin

package LeapTun_lib

import (
	"fmt"

	"golang.zx2c4.com/wireguard/tun"
)

func createDevice(fd int) (tun.Device, error) {
	return nil, fmt.Errorf("TUN file descriptors are only supported on Android, iOS, and macOS")
}
