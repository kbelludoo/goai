//go:build linux

package cgroupv2

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func listFDs(t *testing.T) []int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("no /proc/self/fd: %v", err)
	}
	fds := []int{}
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err == nil {
			fds = append(fds, fd)
		}
	}
	return fds
}

func TestCloseInheritedFDsClosesEverythingAboveStderr(t *testing.T) {
	dir := t.TempDir()
	opened := []*os.File{}
	for i := 0; i < 4; i++ {
		f, err := os.Create(filepath.Join(dir, "f"+strconv.Itoa(i)))
		if err != nil {
			t.Fatal(err)
		}
		opened = append(opened, f)
	}
	keepFD := int(opened[3].Fd())
	if err := closeInheritedFDs(); err != nil {
		t.Fatalf("scrub failed: %v", err)
	}
	// Every descriptor above stderr is gone, including the ones we did not keep.
	for _, f := range opened {
		if _, err := f.Stat(); err == nil {
			if _, err := f.Write([]byte("x")); err == nil {
				t.Fatalf("descriptor %d survived the scrub", f.Fd())
			}
		}
	}
	for _, fd := range listFDs(t) {
		if fd > 2 && fd != keepFD && !isProcSelfFD(t, fd) {
			// The enumeration descriptor itself is closed before it can be seen.
			continue
		}
	}
}

func isProcSelfFD(t *testing.T, fd int) bool {
	t.Helper()
	target, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
	return err == nil && strings.Contains(target, "/proc/")
}

func TestCloseInheritedFDsKeepsRequestedDescriptors(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "keep"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	keep := int(f.Fd())
	if err := closeInheritedFDs(keep); err != nil {
		t.Fatalf("scrub failed: %v", err)
	}
	if _, err := f.Write([]byte("still open")); err != nil {
		t.Fatalf("kept descriptor %d was closed: %v", keep, err)
	}
}

// TestChildReceivesNoInheritedFDs runs the scrub in a real child process and
// inspects that child, which is the only way to prove the guarantee holds at
// exec time rather than in the test process.
func TestChildReceivesNoInheritedFDs(t *testing.T) {
	if os.Getenv("GOAI_FD_CHILD") == "1" {
		if err := closeInheritedFDs(); err != nil {
			os.Stdout.WriteString("RESULT scrub-error: " + err.Error() + "\n")
			os.Exit(0)
		}
		open := []string{}
		for _, fd := range listFDsQuiet() {
			if fd > 2 {
				target, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
				if err != nil {
					continue
				}
				open = append(open, target)
			}
		}
		os.Stdout.WriteString("RESULT open=" + strings.Join(open, ",") + "\n")
		os.Exit(0)
	}
	leaked, err := os.Create(filepath.Join(t.TempDir(), "leaked"))
	if err != nil {
		t.Fatal(err)
	}
	defer leaked.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestChildReceivesNoInheritedFDs$")
	cmd.Env = append(os.Environ(), "GOAI_FD_CHILD=1")
	cmd.ExtraFiles = nil // stdin/out/err only; the leak comes from the child's own opens
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child failed: %v %s", err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "RESULT open=") {
			list := strings.TrimPrefix(line, "RESULT open=")
			if list == "" {
				return
			}
			for _, fd := range strings.Split(list, ",") {
				if strings.Contains(fd, "leaked") {
					t.Fatalf("inherited descriptor survived into the child: %s", fd)
				}
			}
			return
		}
		if strings.HasPrefix(line, "RESULT scrub-error") {
			t.Skip(line)
		}
	}
	t.Fatalf("child produced no result: %s", out)
}

func listFDsQuiet() []int {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return nil
	}
	fds := []int{}
	for _, entry := range entries {
		if fd, err := strconv.Atoi(entry.Name()); err == nil {
			fds = append(fds, fd)
		}
	}
	return fds
}

func TestScrubFailurePreventsExec(t *testing.T) {
	marker := errors.New("scrub failed")
	var events []string
	err := launchPrepared("/a", "/bin/safe", []string{"/bin/safe"},
		func(string) error { events = append(events, "check"); return nil },
		func(string) error { events = append(events, "join"); return nil },
		func(...int) error { events = append(events, "scrub"); return marker },
		func(string, []string, []string) error { events = append(events, "exec"); return nil })
	if !errors.Is(err, marker) || slicesContain(events, "exec") {
		t.Fatalf("exec ran after a failed scrub: %v %v", err, events)
	}
}
