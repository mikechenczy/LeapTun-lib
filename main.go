package LeapTun_lib

import (
	"LeapTun_lib/common"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

var token string

func start(args []string) {
	log.Println("欢迎使用LeapTun")
	log.Println("本程序开源无毒，请放心使用，开源地址：", common.Source)
	log.Println("客户端版本：", common.Version)
	log.Println("管理用户、房间、token，请前往：", common.Website)
	if len(args) < 4 {
		return
	}
	token = args[1]
	fd, err := strconv.Atoi(args[2])
	if err != nil {
		log.Println("fd错误:", err)
		return
	}
	device, err := createDevice(fd)
	if err != nil {
		log.Println("创建 TUN 失败:", err)
		return
	}
	localIP := args[3]
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	stopConn := make(chan struct{})
	go func() {
		for {
			select {
			case <-stopConn:
				log.Println("[INFO] 连接 goroutine 退出")
				return
			default:
			}
			data := map[string]string{"token": token, "version": common.Version}
			jsonBytes, err := json.Marshal(data)
			if err != nil {
				return
			}
			wsURL := fmt.Sprintf(common.Server+"%s", base64.StdEncoding.EncodeToString(jsonBytes))
			parsedURL, err := url.Parse(wsURL)
			if err != nil {
				log.Println("URL Parse err: ", err)
				time.Sleep(5 * time.Second)
				continue
			}
			resolver := &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "udp", "1.1.1.1:53")
				},
			}
			dialer := &net.Dialer{Timeout: 10 * time.Second, Resolver: resolver, KeepAlive: 10 * time.Second}
			client := &http.Client{
				Transport: &http.Transport{DialContext: dialer.DialContext},
				Timeout:   15 * time.Second,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}
			if response, err := client.Head("http://" + parsedURL.Host + parsedURL.Path); err == nil {
				if response.StatusCode == http.StatusMovedPermanently || response.StatusCode == http.StatusFound {
					if newURL, err := url.Parse(response.Header.Get("Location")); err == nil {
						if newURL.Scheme == "http" {
							newURL.Scheme = "ws"
						} else if newURL.Scheme == "https" {
							newURL.Scheme = "wss"
						}
						wsURL = newURL.String()
					}
				}
				_ = response.Body.Close()
			}
			conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
			if err != nil {
				log.Println("[WARN] 连接失败，5秒后重试:", err)
				time.Sleep(5 * time.Second)
				continue
			}
			_, message, err := conn.ReadMessage()
			if err != nil {
				log.Println("[WARN] 读取认证消息失败:", err)
				_ = conn.Close()
				time.Sleep(5 * time.Second)
				continue
			}
			var resp map[string]interface{}
			if err := json.Unmarshal(message, &resp); err != nil {
				log.Println("[WARN] 解析认证消息失败:", err)
				_ = conn.Close()
				time.Sleep(5 * time.Second)
				continue
			}
			log.Println(resp["message"])
			if code, ok := resp["code"].(float64); ok && code != 0 {
				_ = conn.Close()
				time.Sleep(5 * time.Second)
				continue
			}
			common.ConfigureDevice(device, localIP, nil)
			if err := common.Run(conn); err != nil {
				log.Println("[ERROR] 启动 TUN 会话失败:", err)
			}
			time.Sleep(5 * time.Second)
		}
	}()
	<-sig
	common.StopOnce.Do(func() { close(common.Stop) })
	close(stopConn)
	time.Sleep(200 * time.Millisecond)
}

type LogInterface interface{ LogCallback(msg string) }

var logger LogInterface

func SetLogger(l LogInterface) { logger = l }
func androidLog(msg string) {
	if logger != nil {
		logger.LogCallback(msg)
	}
}

func Run(arg string) {
	log.SetFlags(0)
	log.SetOutput(logWriter{})
	log.Println("Go started with arg:", arg)
	start(strings.Fields("tcp_over_ws " + arg))
}

type logWriter struct{}

func (logWriter) Write(p []byte) (n int, err error) {
	androidLog(string(p))
	return len(p), nil
}
