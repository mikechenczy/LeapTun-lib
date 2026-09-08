//go:build android

package LeapTun_lib

import "golang.zx2c4.com/wireguard/tun"

func createDevice(fd int) (tun.Device, error) {
	device, _, err := tun.CreateUnmonitoredTUNFromFD(fd)
	return device, err
}
