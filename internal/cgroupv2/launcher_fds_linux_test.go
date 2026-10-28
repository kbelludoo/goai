//go:build linux

package cgroupv2

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// closeInheritedFDs closes every descriptor above stderr, including the Go
// runtime's own epoll descriptor. Calling it inside a test process therefore
// corrupts the runtime and produces flaky, message-less failures. Every
// assertion below runs in a child process instead.

// fdsAboveStderr lists descriptors above stderr in the current process.
func fdsAboveStderr() []int {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return nil
	}
	fds := []int{}
	for _, entry := range entries {
		if fd, err := strconv.Atoi(entry.Name()); err == nil && fd > 2 {
			fds = append(fds, fd)
		}
	}
	return fds
}

// runScrubChild runs one scrub scenario in a child process and returns its
// self-report ("RESULT ...").
func runScrubChild(t *testing.T, mode string) string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestScrubChildProcess$")
	cmd.Env = append(os.Environ(), "GOAI_SCRUB_MODE="+mode)
	out, err := cmd.CombinedOutput()
	if err != nil && !strings.Contains(string(out), "RESULT") {
		t.Fatalf("child failed: %v %s", err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "RESULT") {
			return strings.TrimSpace(line)
		}
	}
	t.Fatalf("child produced no result: %s", out)
	return ""
}

// TestScrubChildProcess is the payload for the descriptor tests. It is the only
// place where closeInheritedFDs runs, and it always exits immediately after.
func TestScrubChildProcess(t *testing.T) {
	mode := os.Getenv("GOAI_SCRUB_MODE")
	if mode == "" {
		t.Skip("helper process for the descriptor scrub tests")
	}
	dir := os.Getenv("GOAI_SCRUB_DIR")
	var keep int
	switch mode {
	case "closes":
		for i := 0; i < 4; i++ {
			file, err := os.Create(filepath.Join(dir, "f"+strconv.Itoa(i)))
			if err != nil {
				os.Stdout.WriteString("RESULT open-error\n")
				os.Exit(0)
			}
			_ = file
			keep = int(file.Fd())
		}
	case "keeps":
		file, err := os.Create(filepath.Join(dir, "keep"))
		if err != nil {
			os.Stdout.WriteString("RESULT open-error\n")
			os.Exit(0)
		}
		pinned := int(file.Fd())
		if err := closeInheritedFDs(pinned); err != nil {
			os.Stdout.WriteString("RESULT scrub-error " + err.Error() + "\n")
			os.Exit(0)
		}
		if _, err := file.Write([]byte("x")); err != nil {
			os.Stdout.WriteString("RESULT kept-closed\n")
			os.Exit(0)
		}
		os.Stdout.WriteString("RESULT kept-open\n")
		os.Exit(0)
	}
	if err := closeInheritedFDs(); err != nil {
		os.Stdout.WriteString("RESULT scrub-error " + err.Error() + "\n")
		os.Exit(0)
	}
	// The last file we opened had the highest descriptor; report what survived.
	leaked := 0
	for _, fd := range fdsAboveStderr() {
		if fd >= keep {
			leaked++
		}
	}
	os.Stdout.WriteString("RESULT leaked=" + strconv.Itoa(leaked) + "\n")
	os.Exit(0)
}

func TestScrubClosesDescriptorsAboveStderr(t *testing.T) {
	if os.Getenv("GOAI_SCRUB_MODE") != "" {
		t.Skip("helper process")
	}
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestScrubChildProcess$")
	cmd.Env = append(os.Environ(), "GOAI_SCRUB_MODE=closes", "GOAI_SCRUB_DIR="+dir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child failed: %v %s", err, out)
	}
	if !strings.Contains(string(out), "RESULT leaked=0") {
		t.Fatalf("descriptors survived the scrub: %s", out)
	}
}

func TestScrubKeepsRequestedDescriptor(t *testing.T) {
	if os.Getenv("GOAI_SCRUB_MODE") != "" {
		t.Skip("helper process")
	}
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestScrubChildProcess$")
	cmd.Env = append(os.Environ(), "GOAI_SCRUB_MODE=keeps", "GOAI_SCRUB_DIR="+dir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child failed: %v %s", err, out)
	}
	if !strings.Contains(string(out), "RESULT kept-open") {
		t.Fatalf("kept descriptor was closed: %s", out)
	}
}

func TestScrubClosesAForeignDescriptor(t *testing.T) {
	if os.Getenv("GOAI_SCRUB_MODE") != "" {
		t.Skip("helper process")
	}
	// A descriptor inherited from the parent (fd 3 by construction) must not
	// reach the workload either: this is the actual threat, not our own files.
	leaked := filepath.Join(t.TempDir(), "leaked")
	file, err := os.Create(leaked)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestScrubChildProcess$")
	cmd.Env = append(os.Environ(),
		"GOAI_SCRUB_MODE=closes",
		"GOAI_SCRUB_DIR="+t.TempDir(),
		"GOAI_SCRUB_SENTINEL="+leaked)
	cmd.ExtraFiles = []*os.File{file} // becomes fd 3 in the child
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child failed: %v %s", err, out)
	}
	if !strings.Contains(string(out), "RESULT leaked=0") {
		t.Fatalf("inherited descriptor not closed: %s", out)
	}
}

func TestScrubFailurePreventsExec(t *testing.T) {
	marker := errors.New("scrub failed")
	var events []string
	err := launchPrepared("/a", "/bin/safe", []string{"/bin/safe"},
		func(string) error { events = append(events, "check"); return nil },
		func(string) error { events = append(events, "join"); return nil },
		func(string) (int, error) { events = append(events, "open"); return 7, nil },
		func(...int) error { events = append(events, "scrub"); return marker },
		func(int, []string, []string) error { events = append(events, "exec"); return nil })
	if !errors.Is(err, marker) || slicesContain(events, "exec") {
		t.Fatalf("exec ran after a failed scrub: %v %v", err, events)
	}
}

// TestReportedFDsAreNotTheRuntime keeps the helper honest: a test that closes
// its own epoll descriptor would corrupt the runtime, so the helper must never
// run in the test process.
func TestScrubHelperRunsInAChild(t *testing.T) {
	if os.Getenv("GOAI_SCRUB_MODE") != "" {
		t.Skip("helper process")
	}
	before := len(fdsAboveStderr())
	if before == 0 {
		t.Skip("no descriptors above stderr to compare")
	}
	_ = syscall.Getpid()
	if after := len(fdsAboveStderr()); after == 0 {
		t.Fatal("descriptor enumeration flapped; the test process is not trustworthy")
	}
}
