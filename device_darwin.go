//go:build darwin

package LeapTun_lib

import (
	"fmt"
	"os"

	"golang.zx2c4.com/wireguard/tun"
)

func createDevice(fd int) (tun.Device, error) {
	file := os.NewFile(uintptr(fd), "leaptun-tun")
	if file == nil {
		return nil, fmt.Errorf("invalid TUN file descriptor: %d", fd)
	}
	device, err := tun.CreateTUNFromFile(file, 1500)
	if err != nil {
		_ = file.Close()
	}
	return device, err
}
