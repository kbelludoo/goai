//go:build !linux

package isolationprobe

import "errors"

func RunDaemonParent(_, _ string) error { return errors.New("process canary needs Linux") }
func RunDaemonChild(_, _ string) error  { return errors.New("process canary needs Linux") }
