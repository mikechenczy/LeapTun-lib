package common

import (
	"LeapTun_lib/common/version"
	"sync"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type ConnMap struct {
	mu          sync.Mutex
	connWriters map[stack.TransportEndpointID]*ConnHandler
}

func (cm *ConnMap) Set(id stack.TransportEndpointID, connWriter *ConnHandler) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.connWriters[id] = connWriter
}

func (cm *ConnMap) Get(id stack.TransportEndpointID) (*ConnHandler, bool) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	c, ok := cm.connWriters[id]
	return c, ok
}

func (cm *ConnMap) Delete(id stack.TransportEndpointID) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	delete(cm.connWriters, id)
}

func (cm *ConnMap) Keys() []stack.TransportEndpointID {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	keys := make([]stack.TransportEndpointID, 0, len(cm.connWriters))
	for k := range cm.connWriters {
		keys = append(keys, k)
	}
	return keys
}

var cmServer = &ConnMap{
	connWriters: make(map[stack.TransportEndpointID]*ConnHandler),
}

var cmClient = &ConnMap{
	connWriters: make(map[stack.TransportEndpointID]*ConnHandler),
}

func closeConn(connMap *ConnMap, id *stack.TransportEndpointID) {
	connClient, ok := connMap.Get(*id)
	if ok {
		version.DebugLog("收到关闭连接，开始关闭")
		cmClient.Delete(*id)
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := connClient.Close()
			if err != nil {
				version.DebugLog("关闭连接失败：", err)
			}
		}()
	}
}

func closeServerConn(id *stack.TransportEndpointID) {
	closeConn(cmServer, id)
}

func closeClientConn(id *stack.TransportEndpointID) {
	closeConn(cmClient, id)
}

func closeByIP(connMap *ConnMap, ip tcpip.Address) {
	for _, id := range connMap.Keys() {
		if id.LocalAddress == ip {
			conn, ok := connMap.Get(id)
			if ok {
				version.DebugLog("收到关闭连接，开始关闭")
				connMap.Delete(id)
				wg.Add(1)
				go func() {
					defer wg.Done()
					err := conn.Close()
					if err != nil {
						version.DebugLog("关闭连接失败：", err)
					}
				}()
			}
		}
	}
}

func closeServerByIP(ip tcpip.Address) {
	closeByIP(cmServer, ip)
}

func closeClientByIP(ip tcpip.Address) {
	closeByIP(cmClient, ip)
}
