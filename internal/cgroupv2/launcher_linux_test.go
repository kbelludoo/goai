//go:build linux

package cgroupv2

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func TestLaunchSequencingAndEnvIsolation(t *testing.T) {
	var events []string
	needle := "GOAI_TEST_SECRET=must_not_appear"
	t.Setenv("GOAI_TEST_SECRET", "must_not_appear")
	err := launchPrepared("/a", "/bin/safe", []string{"/bin/safe"},
		func(string) error { events = append(events, "check"); return nil },
		func(string) error { events = append(events, "join"); return nil },
		func(string) (int, error) { events = append(events, "open"); return 7, nil },
		func(...int) error { events = append(events, "scrub"); return nil },
		func(fd int, args, env []string) error {
			events = append(events, "exec")
			if fd != 7 || args[0] != "/bin/safe" {
				t.Fatal("bad target")
			}
			if strings.Contains(strings.Join(env, " "), needle) || strings.Contains(strings.Join(env, " "), "GOAI_TEST_SECRET") {
				t.Fatal("host environment leaked")
			}
			if len(env) < 4 {
				t.Fatal("missing safe environment")
			}
			return nil
		})
	if err != nil || !reflect.DeepEqual(events, []string{"check", "join", "open", "scrub", "exec"}) {
		t.Fatalf("bad execution sequence: %v %v", events, err)
	}
}
func TestLaunchDoesNotExecOnCheckOrJoinFailure(t *testing.T) {
	marker := errors.New("failed")
	for _, phase := range []string{"check", "join", "open", "scrub"} {
		var events []string
		err := launchPrepared("/a", "/bin/safe", []string{"/bin/safe"},
			func(string) error {
				events = append(events, "check")
				if phase == "check" {
					return marker
				}
				return nil
			},
			func(string) error {
				events = append(events, "join")
				if phase == "join" {
					return marker
				}
				return nil
			},
			func(string) (int, error) {
				events = append(events, "open")
				if phase == "open" {
					return -1, marker
				}
				return 7, nil
			},
			func(...int) error {
				events = append(events, "scrub")
				if phase == "scrub" {
					return marker
				}
				return nil
			},
			func(int, []string, []string) error { events = append(events, "exec"); return nil })
		if !errors.Is(err, marker) || slicesContain(events, "exec") {
			t.Fatalf("executed after failed %s: %v %v", phase, err, events)
		}
	}
}
func slicesContain(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

// Ordinary temp files must never be accepted as cgroup.procs. This is crucial
// because writing fake files and running /bin/echo would falsely imply safety.
func TestFakeCgroupRejectedBeforeTargetExecution(t *testing.T) {
	folder := t.TempDir()
	marker := filepath.Join(folder, "executed")
	fake := filepath.Join(folder, "goai-fake")
	if err := os.Mkdir(fake, 0700); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"cgroup.procs", "cpu.max", "memory.max", "pids.max"} {
		if err := os.WriteFile(filepath.Join(fake, f), []byte("42"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ticket := Ticket{cgroup: fake, target: "/bin/sh", argv: []string{"/bin/sh", "-c", "touch '" + marker + "'"}}
	if err := ticket.Exec(); !errors.Is(err, ErrLaunchDenied) {
		t.Fatalf("fake cgroup accepted: %v", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("target was executed")
	}
}

func TestExecvePreservesPIDAsIndependentMechanism(t *testing.T) {
	// Mechanism-only test: does NOT claim a real cgroup was joined.
	if os.Getenv("GOAI_EXEC_PID_HELPER") == "1" {
		pid := os.Getpid()
		os.Stdout.WriteString("before=" + intString(pid) + "\n")
		if err := syscall.Exec("/bin/sh", []string{"sh", "-c", "printf 'after=%s\\n' \"$$\""}, []string{"PATH=/bin:/usr/bin"}); err != nil {
			os.Exit(125)
		}
		return
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(self, "-test.run=^TestExecvePreservesPIDAsIndependentMechanism$")
	cmd.Env = append(os.Environ(), "GOAI_EXEC_PID_HELPER=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("mechanism test: %v %s", err, out)
	}
	lines := strings.Fields(string(out))
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "before=") || strings.TrimPrefix(lines[0], "before=") != strings.TrimPrefix(lines[1], "after=") {
		t.Fatalf("PID was not preserved: %q", out)
	}
}
func intString(i int) string { return strconv.Itoa(i) }

// Codes are a machine contract shared by every stage of the sandbox chain. Two
// different failures must never answer to the same code, or an agent cannot
// tell "your path is not a cgroup" from "your root still holds tasks".
//
// This test is deliberately self-contained: it must compile on the launcher
// branch too, where the delegation-root errors of the cgroupv2 package do not
// exist yet, so it asserts the *range* instead of importing those variables.
func TestLauncherCodesAreUniqueAndOutsideTheDelegationRange(t *testing.T) {
	codes := map[string]string{
		"ErrLaunchDenied": codeOf(t, ErrLaunchDenied),
		"ErrJoinFailed":   codeOf(t, ErrJoinFailed),
	}
	seen := map[string]string{}
	for name, code := range codes {
		if other, ok := seen[code]; ok {
			t.Fatalf("%s and %s share code %s", name, other, code)
		}
		seen[code] = name
		number := strings.TrimPrefix(code, "GOAI-CGROUP-")
		if number == code {
			t.Fatalf("%s has an unexpected code shape: %s", name, code)
		}
		value, err := strconv.Atoi(number)
		if err != nil {
			t.Fatalf("%s has a non-numeric code: %s", name, code)
		}
		// 001-010 belong to cgroup discovery, delegation and placement.
		if value < 20 {
			t.Fatalf("%s=%s reuses the delegation range", name, code)
		}
	}
}

func codeOf(t *testing.T, err error) string {
	t.Helper()
	text := err.Error()
	if i := strings.Index(text, ":"); i > 0 {
		return text[:i]
	}
	t.Fatalf("error has no code prefix: %v", err)
	return ""
}
