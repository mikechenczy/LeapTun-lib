//go:build !debug

package version

const Debug = false

func DebugLog(v ...any) {
}
