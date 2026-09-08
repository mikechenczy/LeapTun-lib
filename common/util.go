package common

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func getDstIP(pkt []byte) (dstIP string) {
	if len(pkt) < 20 {
		return ""
	}
	if pkt[0]>>4 != 4 {
		return ""
	}
	ipDst := net.IP(pkt[16:20]).To4()
	if ipDst == nil {
		return ""
	}
	return ipDst.String()
}

func isSameSubnet(ip1Str, ip2Str string) bool {
	ip1 := net.ParseIP(ip1Str).To4()
	ip2 := net.ParseIP(ip2Str).To4()
	if ip1 == nil || ip2 == nil {
		return false
	}

	mask := net.CIDRMask(24, 32) // /24
	network1 := ip1.Mask(mask)
	network2 := ip2.Mask(mask)

	return network1.Equal(network2)
}

func decodeEndpointID(b []byte) *stack.TransportEndpointID {
	if len(b) < 12 {
		log.Println("Invalid byte length for EndpointID")
		return nil
	}

	id := &stack.TransportEndpointID{
		LocalAddress:  tcpip.AddrFrom4Slice(b[0:4]),
		RemoteAddress: tcpip.AddrFrom4Slice(b[4:8]),
		LocalPort:     binary.BigEndian.Uint16(b[8:10]),
		RemotePort:    binary.BigEndian.Uint16(b[10:12]),
	}
	return id
}

func setIPv4Addr(ipAddr string) error {
	if !tunStarted {
		return fmt.Errorf("TUN尚未启动")
	}
	ip = ipAddr
	if configureIP == nil {
		return nil
	}
	return configureIP(ipAddr)
}
