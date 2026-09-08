//go:build debug

package version

import "log"

const Debug = true

func DebugLog(v ...any) {
	log.Println(v)
}
