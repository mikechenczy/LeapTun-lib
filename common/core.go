package common

import (
	"LeapTun_lib/common/version"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/inancgumus/screen"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"golang.zx2c4.com/wireguard/tun"
)

const tunPacketOffset = 14
const maxLimit = 1 << 23

type packet struct {
	dstIP string
	data  []byte
}

var (
	tunStarted  = false
	ip          = "10.0.0.0"
	initialIP   = "10.0.0.0"
	configureIP func(string) error
	Stop        = make(chan struct{})
	wg          sync.WaitGroup
	StopOnce    sync.Once
	devName     string
	dev         tun.Device
	c           *Convertor
	mtu         int
	allClosed   bool
	closeLocker sync.Mutex
	firewall    = FirewallConfig{
		Default: true,
	}
)

func closeAll(conn *websocket.Conn) {
	closeLocker.Lock()
	defer closeLocker.Unlock()
	if allClosed {
		return
	}
	allClosed = true
	c.Close()
	_ = dev.Close()
	_ = conn.Close()
	close(wsWriteQueue)
	for _, id := range cmClient.Keys() {
		conn, ok := cmClient.Get(id)
		if !ok {
			continue
		}
		cmClient.Delete(id)
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = conn.Close()
		}()
	}
	for _, id := range cmServer.Keys() {
		conn, ok := cmServer.Get(id)
		if !ok {
			continue
		}
		cmServer.Delete(id)
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = conn.Close()
		}()
	}
}

// ConfigureDevice supplies the TUN device owned by the platform entry point.
// The common package closes the device when the session ends. setIP is optional;
// mobile callers normally configure the address outside Go and can leave it nil.
func ConfigureDevice(device tun.Device, localIP string, setIP func(string) error) {
	dev = device
	initialIP = localIP
	configureIP = setIP
}

func Run(wsConn *websocket.Conn) error {
	allClosed = false
	if dev == nil {
		return fmt.Errorf("TUN device has not been configured")
	}
	tunStarted = true
	ip = initialIP

	devName, _ = dev.Name()
	mtu, _ = dev.MTU()
	log.Printf("[INFO] TUN 已创建: %s (MTU=%d)", devName, mtu)

	wg = sync.WaitGroup{}
	Stop = make(chan struct{})
	StopOnce = sync.Once{}
	wsOnce = sync.Once{}
	wsWriteQueue = make(chan msg, 1024)
	sendQueue := make(chan packet, 1<<14)

	startConvertor(wsConn)

	startUploadThread(wsConn, sendQueue)

	startTUNUploadThread(wsConn, sendQueue)

	startDownloadThread(wsConn)

	// 等待 goroutine 退出
	wg.Wait()
	ip = ""
	tunStarted = false
	closeAll(wsConn)
	close(sendQueue)
	log.Println("[INFO] run() 已退出")
	return nil
}

func startDownloadThread(wsConn *websocket.Conn) {
	// 下行循环（改为二进制格式）
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-Stop:
				log.Println("[INFO] 下行 goroutine 退出")
				closeAll(wsConn)
				return
			default:
			}

			_, message, err := wsConn.ReadMessage()
			if err != nil {
				select {
				case <-Stop:
					log.Println("[INFO] 下行 goroutine 退出")
					closeAll(wsConn)
					return
				default:
				}
				log.Println("[ERROR] 读取消息失败:", err)
				StopOnce.Do(func() { close(Stop) })
				continue
			}

			if len(message) < 1 {
				continue
			}

			msgType := message[0]
			data := message[1:]

			if msgType == 0 {
				// JSON 消息
				var msg Message
				if err := json.Unmarshal(data, &msg); err != nil {
					log.Println("[ERROR] 解析 JSON 失败:", err)
					continue
				}

				switch msg.Type {
				case "updateStatus":
					var status struct {
						Username           string `json:"username"`
						RoomName           string `json:"roomName"`
						IP                 string `json:"ip"`
						RemainingBandwidth string `json:"remainingBandwidth"`
						RoomMembers        []struct {
							Name   string `json:"name"`
							IP     string `json:"ip"`
							Online bool   `json:"online"`
						} `json:"roomMembers"`
					}
					if err := json.Unmarshal(msg.Data, &status); err != nil {
						log.Println("[ERROR] 解析 updateStatus 失败:", err)
						continue
					}

					if !version.Debug {
						screen.Clear()
						screen.MoveTopLeft()
					}
					fmt.Println("用户名:", status.Username)
					fmt.Println("房间名:", status.RoomName)
					fmt.Println("当前 IP:", status.IP)
					fmt.Println("房间剩余带宽:", status.RemainingBandwidth)
					fmt.Println("成员列表:")
					for _, m := range status.RoomMembers {
						if m.Online {
							fmt.Printf(" - %s %s (%s)\n", m.Name, m.IP, "在线")
						} else {
							fmt.Printf(" - %s %s (%s)\n", m.Name, m.IP, "离线")
						}
					}

					if ip != status.IP {
						if err := setIPv4Addr(status.IP); err != nil {
							log.Println("[ERROR] 设置IP失败:", err)
						}
					}
					break
				case "firewall":
					if err := json.Unmarshal(msg.Data, &firewall); err != nil {
						log.Println("[ERROR] 解析 firewall 失败:", err)
						continue
					}
					break
				}
			} else if msgType == 1 {
				if len(data) < 4 {
					continue
				}
				//dstIP := net.IP(data[0:4]).String()
				buf := data[4:]

				for len(buf) >= 2 {
					pLen := int(binary.BigEndian.Uint16(buf[0:2]))
					if pLen < 0 || len(buf) < 2+pLen {
						log.Println("[WARN] 下行包长度异常，丢弃剩余数据")
						break
					}
					payload := buf[2 : 2+pLen]

					if _, err := WriteBytesWithLenToTun(payload, pLen); err != nil {
						log.Println("[ERROR] 写入 TUN 失败:", err)
					} else if version.Debug {
						log.Printf("[DEBUG] 写入 TUN, len=%d", pLen)
					}

					buf = buf[2+pLen:]
				}
			} else if msgType == 2 {
				if version.Debug {
					log.Println("收到TCP数据")
				}
				data = data[4:]
				id := decodeEndpointID(data)
				localConnHandler, ok := cmClient.Get(*id)
				if ok {
					if version.Debug {
						log.Println("存在Conn继续write")
					}
					localConnHandler.Write(data[12:])
					continue
				} else {
					dialAndRegister(wsConn, id, data)
				}
			} else if msgType == 3 {
				if version.Debug {
					//log.Println("收到TCP数据返回")
				}
				data = data[4:]
				id := decodeEndpointID(data)
				tunConnHandler, ok := cmServer.Get(*id)
				if ok {
					if version.Debug {
						//log.Println("收到TCP数据返回，数据写入")
					}
					tunConnHandler.Write(data[12:])
				}
			} else if msgType == 4 {
				if version.Debug {
					log.Println("收到关闭连接")
				}
				data = data[4:]
				id := decodeEndpointID(data)
				closeServerConn(id)
				closeClientConn(id)
			} else if msgType == 5 {
				if version.Debug {
					log.Println("收到来自服务器自发的关闭连接")
				}
				ip := tcpip.AddrFrom4Slice(data[0:4])
				closeServerByIP(ip)
				closeClientByIP(ip)
			} else if msgType == 6 {
				if version.Debug {
					log.Println("6, 收到请求dial")
				}
				data = data[4:]
				id := decodeEndpointID(data)
				_, ok := cmClient.Get(*id)
				if ok {
					if version.Debug {
						log.Println("6, 存在Conn")
					}
					continue
				} else {
					dialAndRegister(wsConn, id, nil)
				}
			}
			//If codes are added here, remember to check whether upper codes should call `continue`.
		}
	}()

}

func startTUNUploadThread(wsConn *websocket.Conn, sendQueue chan packet) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		batchSizeBytes := 64 * 1024
		flushInterval := 5 * time.Millisecond

		var curIP string
		var buf []byte
		timer := time.NewTimer(flushInterval)
		defer timer.Stop()

		flush := func() {
			if len(buf) > 0 && curIP != "" {
				ipBytes := net.ParseIP(curIP).To4()
				if ipBytes == nil {
					buf = buf[:0]
					curIP = ""
					return
				}

				// 整帧格式: [1][dstIP(4)][buf...]
				out := make([]byte, 5+len(buf))
				out[0] = 1
				copy(out[1:5], ipBytes)
				copy(out[5:], buf)

				writeMessageAsync(wsConn, websocket.BinaryMessage, out)
				buf = buf[:0]
				curIP = ""
			}
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(flushInterval)
		}

		for {
			select {
			case <-Stop:
				flush()
				log.Println("[INFO] 发送 goroutine 退出")
				closeAll(wsConn)
				return
			case p, ok := <-sendQueue:
				if !ok {
					flush()
					log.Println("[INFO] 发送队列已关闭，退出发送 goroutine")
					return
				}
				// 如果当前 IP 为空，初始化
				if curIP == "" {
					curIP = p.dstIP
				}
				// 如果 IP 不同，先 flush 再开启新批次
				if curIP != p.dstIP {
					flush()
					curIP = p.dstIP
				}
				// 写入 [len|payload]
				if len(buf)+2+len(p.data) > batchSizeBytes {
					flush()
					curIP = p.dstIP
				}
				tmp := make([]byte, 2+len(p.data))
				binary.BigEndian.PutUint16(tmp[0:2], uint16(len(p.data)))
				copy(tmp[2:], p.data)
				buf = append(buf, tmp...)
			case <-timer.C:
				flush()
			}
		}
	}()
}

func startUploadThread(wsConn *websocket.Conn, sendQueue chan packet) {
	// 批量缓冲
	batch := dev.BatchSize()
	if batch <= 0 {
		batch = 8
	}
	buffs := make([][]byte, batch)
	sizes := make([]int, batch)
	for i := range buffs {
		buffs[i] = make([]byte, mtu+tunPacketOffset)
	}

	// 上行 goroutine tun网卡接收本地要访问远端的包，tcp通过convertor转为net.conn（防止大量ack和拆包之类的），其余直接发送
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-Stop:
				log.Println("[INFO] 上行 goroutine 退出")
				closeAll(wsConn)
				return
			default:
			}
			n, err := dev.Read(buffs, sizes, tunPacketOffset)
			if err != nil {
				select {
				case <-Stop:
					log.Println("[INFO] 上行 goroutine 退出")
					return
				default:
				}
				log.Println("[ERROR] TUN Read 出错:", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
			for i := 0; i < n; i++ {
				data := buffs[i][tunPacketOffset : tunPacketOffset+sizes[i]]
				dstIP := getDstIP(data)
				if dstIP == "" || ip == "" || !isSameSubnet(dstIP, ip) || ip == dstIP {
					continue
				}
				if len(data) <= 9 {
					continue
				}
				if data[9] == 6 {
					c.SendBytes(data)
					continue
				}
				if data[9] != 17 && data[9] != 1 && data[9] != 2 {
					continue
				}
				p := packet{dstIP: dstIP, data: append([]byte(nil), data...)}
				select {
				case sendQueue <- p:
				default:
					<-sendQueue
					sendQueue <- p
				}
			}
		}
	}()
}

func startConvertor(wsConn *websocket.Conn) {
	c = NewConvertor(WriteBytesToTun, uint32(mtu))

	//这个conn是虚拟远方的conn,LocalAddress实际上是DstIP
	c.StartTCPForwarder(func(tunConn net.Conn, id *stack.TransportEndpointID) {
		if version.Debug {
			log.Println("拿到连接了！！！")
			log.Println(id.LocalAddress)
			log.Println("cmServer count: ", len(cmServer.Keys()))
		}
		dialReq := make([]byte, 17)
		dialReq[0] = 6
		copy(dialReq[1:5], id.LocalAddress.AsSlice())
		copyIdToData(dialReq, id)
		writeMessageAsync(wsConn, websocket.BinaryMessage, dialReq)

		tunConnHandler := NewConnHandler(tunConn, 1<<14, 0, 0, func(cw *ConnHandler, n int, err error) {
			if err != nil {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if version.Debug {
						log.Println("数据写入失败")
					}
					cmServer.Delete(*id)
					_ = cw.Close()
					serverData := make([]byte, 17)
					serverData[0] = 4
					copy(serverData[1:5], id.LocalAddress.AsSlice())
					copyIdToData(serverData, id)
					writeMessageAsync(wsConn, websocket.BinaryMessage, serverData)
				}()
			}
		})
		cmServer.Set(*id, tunConnHandler)
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 1<<14)
			errStop := false
			for {
				select {
				case <-Stop:
					cmServer.Delete(*id)
					_ = tunConnHandler.Close()
					log.Println("[INFO] TCP Forwarder goroutine 退出")
					closeAll(wsConn)
					return
				default:
				}
				if errStop {
					serverData := make([]byte, 17)
					serverData[0] = 4
					copy(serverData[1:5], id.LocalAddress.AsSlice())
					copyIdToData(serverData, id)
					writeMessageAsync(wsConn, websocket.BinaryMessage, serverData)
					return
				}
				n, err := tunConnHandler.conn.Read(buf)
				if err != nil {
					if version.Debug {
						log.Println("Read error:", err)
					}
					cmServer.Delete(*id)
					_ = tunConnHandler.Close()
					errStop = true
				}

				data := buf[:n]

				serverData := make([]byte, 17+len(data))

				serverData[0] = 2
				copy(serverData[1:5], id.LocalAddress.AsSlice())
				copyIdToData(serverData, id)
				copy(serverData[17:], data)

				writeMessageAsync(wsConn, websocket.BinaryMessage, serverData)
			}
		}()
	})
}

func dialAndRegister(wsConn *websocket.Conn, id *stack.TransportEndpointID, data []byte) bool {
	if version.Debug {
		log.Println("dial: " + ip + ":" + fmt.Sprintf("%d", id.LocalPort))
	}
	if !firewall.match(id.RemoteAddress.String(), id.LocalPort) {
		log.Println("dial failed:", " Firewall denied")
		return true
	}
	var dialIp string
	if firewall.Local {
		dialIp = "127.0.0.1"
	} else {
		dialIp = ip
	}
	localConn, err := net.Dial("tcp", dialIp+":"+fmt.Sprintf("%d", id.LocalPort))
	if err != nil {
		log.Println("dial err:", err)
		return true
	}
	if data != nil {
		_, err = localConn.Write(data[12:])
	}
	if err != nil {
		log.Println("write err:", err)
		_ = localConn.Close()
		return true
	}
	registerLocalConnHandler(wsConn, localConn, id)
	return false
}

func copyIdToData(data []byte, id *stack.TransportEndpointID) {
	copy(data[5:9], id.LocalAddress.AsSlice())
	copy(data[9:13], id.RemoteAddress.AsSlice())
	binary.BigEndian.PutUint16(data[13:15], id.LocalPort)
	binary.BigEndian.PutUint16(data[15:17], id.RemotePort)
}

func registerLocalConnHandler(wsConn *websocket.Conn, localConn net.Conn, id *stack.TransportEndpointID) {
	localConnHandler := NewConnHandler(localConn, 1024, 0, maxLimit, func(cw *ConnHandler, n int, err error) {
		if err != nil {
			wg.Add(1)
			go func() {
				defer wg.Done()
				cmClient.Delete(*id)
				_ = cw.Close()
				serverData := make([]byte, 17)
				serverData[0] = 4
				copy(serverData[1:5], id.RemoteAddress.AsSlice())
				copyIdToData(serverData, id)
				writeMessageAsync(wsConn, websocket.BinaryMessage, serverData)
			}()
		}
	})
	cmClient.Set(*id, localConnHandler)
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 1<<14)
		errStop := false
		for {
			select {
			case <-Stop:
				cmClient.Delete(*id)
				_ = localConnHandler.Close()
				log.Println("[INFO] Local TCP Forwarder goroutine 退出")
				closeAll(wsConn)
				return
			default:
			}
			if errStop {
				serverData := make([]byte, 17)
				serverData[0] = 4
				copy(serverData[1:5], id.RemoteAddress.AsSlice())
				copyIdToData(serverData, id)
				writeMessageAsync(wsConn, websocket.BinaryMessage, serverData)
				return
			}
			n, err := localConnHandler.Read(buf)
			if err != nil {
				if version.Debug {
					log.Println("Dial Read error:", err)
				}
				cmClient.Delete(*id)
				_ = localConnHandler.Close()
				errStop = true
			}
			serverData := make([]byte, 17+n)
			serverData[0] = 3
			copy(serverData[1:5], id.RemoteAddress.AsSlice())
			copyIdToData(serverData, id)
			copy(serverData[17:], buf[:n])
			writeMessageAsync(wsConn, websocket.BinaryMessage, serverData)
		}
	}()
}

type msg struct {
	typ  int
	data []byte
}

var (
	wsWriteQueue chan msg
	wsOnce       sync.Once
)

func initWsWriter(wsConn *websocket.Conn) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-Stop:
				log.Println("[INFO] 异步发送 goroutine 退出")
				closeAll(wsConn)
				return
			case m := <-wsWriteQueue:
				_ = wsConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if err := wsConn.WriteMessage(m.typ, m.data); err != nil {
					select {
					case <-Stop:
						log.Println("[INFO] 异步发送 goroutine 退出")
						closeAll(wsConn)
						return
					default:
					}
					log.Println("[ERROR] 发送失败:", err)
					StopOnce.Do(func() { close(Stop) })
				}
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		currentLimit := maxLimit
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-Stop:
				return
			case <-ticker.C:
				queueUsage := float64(len(wsWriteQueue)) / float64(cap(wsWriteQueue))

				needToSet := false
				// 调整策略
				if queueUsage > 0.8 {
					currentLimit -= 1 << 18 //256KB/s
					if currentLimit < 1 {
						currentLimit = 1
					}
					needToSet = true
				} else if queueUsage < 0.01 && currentLimit != maxLimit {
					currentLimit += 1 << 16 //64KB/s
					if currentLimit > maxLimit {
						currentLimit = maxLimit
					}
					needToSet = true
				}

				if needToSet {
					for _, id := range cmClient.Keys() {
						conn, ok := cmClient.Get(id)
						if !ok {
							continue
						}
						conn.SetReadLimit(currentLimit)
						if version.Debug {
							log.Printf("[Limiter] set client limit=%d", currentLimit)
						}
					}
					for _, id := range cmServer.Keys() {
						conn, ok := cmServer.Get(id)
						if !ok {
							continue
						}
						conn.SetReadLimit(currentLimit)
					}
				}
				if version.Debug {
					log.Printf("[Limiter] queueUsage=%.2f, newLimit=%d", queueUsage, currentLimit)
				}
			}
		}
	}()
}

func writeMessageAsync(wsConn *websocket.Conn, messageType int, data []byte) {
	closeLocker.Lock()
	defer closeLocker.Unlock()
	wsOnce.Do(func() { initWsWriter(wsConn) })
	if !allClosed {
		wsWriteQueue <- msg{typ: messageType, data: data}
	}
}

func WriteBytesToTun(payload []byte) (int, error) {
	out := make([]byte, tunPacketOffset+len(payload))
	copy(out[tunPacketOffset:], payload)
	return dev.Write([][]byte{out}, tunPacketOffset)
}

func WriteBytesWithLenToTun(payload []byte, pLen int) (int, error) {
	out := make([]byte, tunPacketOffset+pLen)
	copy(out[tunPacketOffset:], payload)
	return dev.Write([][]byte{out}, tunPacketOffset)
}
