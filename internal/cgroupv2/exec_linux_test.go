//go:build linux

package cgroupv2

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestOpenExecutablePinsRegularFile(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "helper.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	fd, err := openExecutable(script)
	if err != nil {
		t.Fatalf("executable rejected: %v", err)
	}
	syscall.Close(fd)
}

func TestOpenExecutableRefusesNonExecutableAndDirectories(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain.txt")
	if err := os.WriteFile(plain, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{plain, dir} {
		if _, err := openExecutable(target); !errors.Is(err, ErrExecutableChanged) {
			t.Errorf("%q accepted: %v", target, err)
		}
	}
}

func TestOpenExecutableRefusesSwappableDirectory(t *testing.T) {
	// A directory anyone but the owner can write could swap the file between
	// validation and exec; the pin removes the file swap, this removes the rest.
	dir := t.TempDir()
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "helper.sh")
	if err := os.WriteFile(target, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := openExecutable(target); !errors.Is(err, ErrExecutableChanged) {
		t.Fatalf("writable parent directory accepted: %v", err)
	}
}

func TestExecveatRunsThePinnedInode(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// The helper pins the very file that is already running and re-execs it with
	// a marker, so a successful exec proves descriptor-based execution works.
	out, err := runWithExecveat(self)
	if err != nil {
		t.Skipf("execveat unavailable in this sandbox: %v (output %q)", err, out)
	}
	if !strings.Contains(out, "CHILD-RAN") {
		t.Fatalf("pinned exec did not run the child: %q", out)
	}
}

func TestExecveatChildWitness(t *testing.T) {
	if os.Getenv("GOAI_EXECVEAT_CHILD") != "1" {
		t.Skip("helper process for TestExecveatRunsThePinnedInode")
	}
	os.Stdout.WriteString("CHILD-RAN\n")
	os.Exit(0)
}

func TestExecveatRejectsEmptyArgv(t *testing.T) {
	if err := execveatFD(0, nil, nil); !errors.Is(err, ErrLaunchDenied) {
		t.Fatalf("empty argv accepted: %v", err)
	}
}

func TestExecveatReportsKernelRefusal(t *testing.T) {
	// A read-only descriptor of a non-executable file must fail loudly rather
	// than return nil, so the launcher exits 127 instead of pretending success.
	path := filepath.Join(t.TempDir(), "data")
	if err := os.WriteFile(path, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	err = execveatFD(fd, []string{"data"}, []string{"PATH=/bin"})
	if err == nil {
		t.Fatal("execveat reported success without executing")
	}
	if !errors.Is(err, ErrLaunchDenied) {
		t.Fatalf("unexpected error type: %v", err)
	}
}

// runWithExecveat executes the pinned file in a helper process through a small
// re-exec of the test binary, because execveat cannot return to the caller.
func runWithExecveat(path string) (string, error) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestExecveatHelperProcess$")
	cmd.Env = append(os.Environ(),
		"GOAI_EXECVEAT_HELPER=1",
		"GOAI_EXECVEAT_PATH="+path)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestExecveatHelperProcess(t *testing.T) {
	if os.Getenv("GOAI_EXECVEAT_HELPER") != "1" {
		t.Skip("helper process")
	}
	target := os.Getenv("GOAI_EXECVEAT_PATH")
	fd, err := openExecutable(target)
	if err != nil {
		os.Stdout.WriteString("PIN-FAILED\n")
		os.Exit(1)
	}
	err = execveatFD(fd, []string{target, "-test.run=^TestExecveatChildWitness$"},
		[]string{"GOAI_EXECVEAT_CHILD=1", "PATH=/usr/bin:/bin"})
	os.Stdout.WriteString("EXEC-FAILED: " + err.Error() + "\n")
	os.Exit(1)
}
