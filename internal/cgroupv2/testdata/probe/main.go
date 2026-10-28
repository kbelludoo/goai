// A bounded, trusted cgroup integration probe. Not a fork bomb: at most 64
// short-lived helper processes are spawned and always reaped or killed.
package main

import (
	"fmt"
	"github.com/kbelludoo/goai/internal/cgroupv2"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "child" {
		time.Sleep(2 * time.Second)
		return
	}
	if len(os.Args) != 3 || os.Args[1] != "probe" {
		os.Exit(2)
	}
	want := os.Args[2]
	loc, err := cgroupv2.Discover()
	if err != nil || loc.Parent() != want {
		fmt.Fprintln(os.Stderr, "not in expected cgroup:", loc.Parent(), want, err)
		os.Exit(3)
	}
	beforeRaw, err := os.ReadFile(want + "/pids.events")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(4)
	}
	before, err := failures(beforeRaw)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(5)
	}
	self, err := os.Executable()
	if err != nil {
		os.Exit(6)
	}
	var launched []*exec.Cmd
	denied := 0
	for i := 0; i < 64; i++ {
		c := exec.Command(self, "child")
		if err := c.Start(); err != nil {
			denied++
			continue
		}
		launched = append(launched, c)
	}
	for _, c := range launched {
		_ = c.Wait()
	}
	afterRaw, err := os.ReadFile(want + "/pids.events")
	if err != nil {
		os.Exit(7)
	}
	after, err := failures(afterRaw)
	if err != nil || after <= before {
		fmt.Fprintf(os.Stderr, "pids limit not observed: before=%d after=%d denied=%d err=%v\n", before, after, denied, err)
		os.Exit(8)
	}
	fmt.Printf("contained: successful=%d denied=%d pids.max_events=%s\n", len(launched), denied, strconv.FormatUint(after-before, 10))
}
func failures(raw []byte) (uint64, error) {
	fields := strings.Fields(string(raw))
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "max" {
			return strconv.ParseUint(fields[i+1], 10, 64)
		}
	}
	return 0, fmt.Errorf("missing max event")
}
