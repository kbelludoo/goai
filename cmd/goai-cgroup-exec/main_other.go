//go:build !linux

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "goai-cgroup-exec: Linux cgroup v2 is required")
	os.Exit(126)
}
