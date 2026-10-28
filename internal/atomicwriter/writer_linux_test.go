//go:build linux

package atomicwriter

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func fixture(t *testing.T) (string, []byte) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "wallet.go")
	source := []byte("package wallet\nvar balance = 100\n")
	if err := os.WriteFile(path, source, 0640); err != nil {
		t.Fatal(err)
	}
	return path, source
}
func TestReplacePreservesModesAndReplacesAtomically(t *testing.T) {
	path, source := fixture(t)
	next := []byte("package wallet\nvar balance = 70\n")
	if err := Replace(path, digest(source), next); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(next) {
		t.Fatalf("got %s", got)
	}
	stat, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if stat.Mode().Perm() != 0640 {
		t.Fatalf("mode %v", stat.Mode())
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".goai-stage-*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("unremoved stages: %v", matches)
	}
}
func TestDetectsExternalChangeBeforeFinalCheck(t *testing.T) {
	path, source := fixture(t)
	outside := []byte("package wallet\nvar balance = 999\n")
	err := replace(path, digest(source), []byte("package wallet\nvar balance = 70\n"), func() error {
		return os.WriteFile(path, outside, 0600) // non-cooperative IDE simulation
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("wanted conflict: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != string(outside) {
		t.Fatalf("writer clobbered external change: %s", got)
	}
}
func TestDetectsSameContentExternalReplacementByInode(t *testing.T) {
	path, source := fixture(t)
	err := replace(path, digest(source), []byte("package wallet\nvar balance = 70\n"), func() error {
		other := filepath.Join(filepath.Dir(path), "replacement")
		if err := os.WriteFile(other, source, 0640); err != nil {
			return err
		}
		return os.Rename(other, path) // same bytes, different inode
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("expected identity conflict: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != string(source) {
		t.Fatalf("unexpected content: %s", got)
	}
}
func TestRejectsWrongOriginalRevision(t *testing.T) {
	path, source := fixture(t)
	err := Replace(path, strings.Repeat("0", 64), []byte("malicious"))
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("expected conflict: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != string(source) {
		t.Fatal("modified stale source")
	}
}
func TestRejectsCooperativeConcurrentLock(t *testing.T) {
	path, source := fixture(t)
	lockPath := filepath.Join(filepath.Dir(path), ".wallet.go.goai.commit.lock")
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	err = Replace(path, digest(source), []byte("candidate"))
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("expected lock conflict: %v", err)
	}
}
func TestRejectsSymlinkTargetAndLock(t *testing.T) {
	path, source := fixture(t)
	link := filepath.Join(filepath.Dir(path), "link.go")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := Replace(link, digest(source), []byte("candidate")); !errors.Is(err, ErrUnsafeTarget) {
		t.Fatalf("expected symlink refusal: %v", err)
	}
	lockPath := filepath.Join(filepath.Dir(path), ".wallet.go.goai.commit.lock")
	if err := os.Symlink(path, lockPath); err != nil {
		t.Fatal(err)
	}
	if err := Replace(path, digest(source), []byte("candidate")); !errors.Is(err, ErrUnsafeTarget) {
		t.Fatalf("expected unsafe lock refusal: %v", err)
	}
}
func TestRejectsRelativePaths(t *testing.T) {
	if err := Replace("wallet.go", strings.Repeat("0", 64), nil); !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("relative path: %v", err)
	}
}
