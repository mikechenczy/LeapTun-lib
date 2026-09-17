package common

import "encoding/json"

const (
	Server  = ""
	Version = "v1.6"
	Website = "https://tun.mjczy.top/"
	Source  = "https://github.com/mikechenczy/LeapTun"
)

type Message struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}
