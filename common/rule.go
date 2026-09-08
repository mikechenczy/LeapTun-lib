package common

import "net"

type FirewallConfig struct {
	Local   bool   `json:"local"`
	Default bool   `json:"default"`
	Allow   []Rule `json:"allow"`
	Deny    []Rule `json:"deny"`
}

type Rule struct {
	IP   string `json:"ip"`
	Port uint16 `json:"port"`
}

func matchRule(r Rule, ip string, port uint16) bool {
	if r.IP != "*" {
		target := net.ParseIP(ip)
		if target == nil {
			return false
		}

		if _, network, err := net.ParseCIDR(r.IP); err == nil {
			if !network.Contains(target) {
				return false
			}
		} else {
			if r.IP != ip {
				return false
			}
		}
	}

	if r.Port != 0 && r.Port != port {
		return false
	}

	return true
}

func (f *FirewallConfig) match(ip string, port uint16) bool {
	// 黑名单优先
	for _, r := range f.Deny {
		if matchRule(r, ip, port) {
			return false
		}
	}
	// 白名单
	for _, r := range f.Allow {
		if matchRule(r, ip, port) {
			return true
		}
	}
	// 默认
	return f.Default
}
