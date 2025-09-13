package LeapTun_lib

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
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

const (
	server  = ""
	version = "v1.3"
	website = "https://tun.mjczy.top/"
	source  = "https://github.com/mikechenczy/LeapTun-lib"
	debug   = false
)

var token string

type Message struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

func start(args []string) {
	log.Println("欢迎使用LeapTun")
	log.Println("本程序开源无毒，请放心使用，开源地址：", source)
	log.Println("客户端版本：", version)
	log.Println("管理用户、房间、token，请前往：", website)
	if len(args) < 4 {
		return
	}
	log.Print("读取到 token: ")
	token = args[1]
	log.Println(token)
	fd, err := strconv.Atoi(args[2])
	if err != nil {
		log.Println("fd错误:", err)
		return
	}
	localIp := args[3]

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
			// 构造 JSON 并 Base64 编码
			data := map[string]string{
				"token":   token,
				"version": version,
			}
			jsonBytes, err := json.Marshal(data)
			if err != nil {
				return
			}
			wsURL := fmt.Sprintf(server+"%s", base64.StdEncoding.EncodeToString(jsonBytes))

			parsedURL, err := url.Parse(wsURL)
			if err != nil {
				log.Println("URL Parse err: ", err)
				time.Sleep(5 * time.Second)
				continue
			}
			// 创建 HTTP 客户端（支持重定向）
			client := &http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}

			// 先发送 HTTP 请求，检查是否重定向
			response, err := client.Head("http://" + parsedURL.Host + parsedURL.Path)
			if err == nil {
				// 如果返回 301/302，获取新的 Location
				if response.StatusCode == http.StatusMovedPermanently || response.StatusCode == http.StatusFound {
					newLocation := response.Header.Get("Location")

					// 解析新地址
					newURL, err := url.Parse(newLocation)
					if err != nil {
						log.Println("Parse URL failed: ", err)
						time.Sleep(5 * time.Second)
						continue
					}

					// 修改 ws/wss 前缀
					if newURL.Scheme == "http" {
						newURL.Scheme = "ws"
					} else if newURL.Scheme == "https" {
						newURL.Scheme = "wss"
					}

					// 更新连接地址
					wsURL = newURL.String()
				}
				err = response.Body.Close()
				if err != nil {
					log.Println("[WARN] 连接失败，5秒后重试:", err)
					time.Sleep(5 * time.Second)
					continue
				}
			}

			// 尝试连接
			conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
			if err != nil {
				log.Println("[WARN] 连接失败，5秒后重试:", err)
				time.Sleep(5 * time.Second)
				continue
			}

			log.Println("[INFO] 已连接")

			// 读取一次服务器返回的认证消息
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
				log.Println("[WARN] 认证失败，5s后重连:", err)
				_ = conn.Close()
				time.Sleep(5 * time.Second)
				continue
			}

			// 调用核心逻辑 run(conn)，断开后自动重连
			run(conn, fd, localIp)

			// run 返回说明 WebSocket 已断开
			log.Println("[WARN] WebSocket 断开，5秒后重连...")
			time.Sleep(5 * time.Second)
		}
	}()

	<-sig
	stopOnce.Do(func() { close(stop) })
	close(stopConn)
	time.Sleep(200 * time.Millisecond) // 等 goroutine 优雅退出
	log.Println("[INFO] 客户端退出")
}

type LogInterface interface {
	LogCallback(msg string)
}

var logger LogInterface

func SetLogger(log LogInterface) {
	logger = log
}

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
