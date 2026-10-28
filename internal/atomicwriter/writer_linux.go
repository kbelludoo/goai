//go:build linux

// Package atomicwriter performs cooperative, single-file, revision-checked
// replacement. It is NOT a filesystem compare-and-swap, and does not sandbox
// untrusted code or prevent non-cooperating filesystem writers.
package atomicwriter

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

var (
	ErrConflict     = errors.New("GOAI-WRITE-001: source revision or identity changed")
	ErrLocked       = errors.New("GOAI-WRITE-002: another cooperative writer holds the lock")
	ErrUnsafeTarget = errors.New("GOAI-WRITE-003: target or lock is not a regular file")
	ErrInvalidPath  = errors.New("GOAI-WRITE-004: expected canonical absolute source path")
	ErrUnsupported  = errors.New("GOAI-WRITE-005: atomicwriter is unsupported on this platform")
)

// Replace stages data in the target's directory, locks a persistent sidecar
// with Linux flock, verifies original SHA-256 *after staging*, then renames.
// Non-cooperative editors are not synchronized. A change in the small window
// AFTER the last check but BEFORE rename is not detectable atomically.
// The caller is responsible for workspace authorization and safe parent dirs.
func Replace(path, expectedSHA256 string, candidate []byte) error {
	return replace(path, expectedSHA256, candidate, nil)
}

// Test hook is executed before the final revision check. Not exported.
func replace(path, expectedSHA256 string, candidate []byte, beforeFinalCheck func() error) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrInvalidPath
	}
	if len(expectedSHA256) != sha256.Size*2 {
		return ErrConflict
	}
	if _, err := hex.DecodeString(expectedSHA256); err != nil {
		return ErrConflict
	}
	directory := filepath.Dir(path)
	lockName := filepath.Join(directory, "."+filepath.Base(path)+".goai.commit.lock")
	lock, err := openNoFollow(lockName, syscall.O_RDWR|syscall.O_CREAT, 0600)
	if err != nil {
		return fmt.Errorf("open coordination lock: %w", err)
	}
	defer lock.Close()
	info, err := lock.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return ErrUnsafeTarget
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return ErrLocked
		}
		return fmt.Errorf("acquire cooperative lock: %w", err)
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)

	original, originalInfo, err := current(path)
	if err != nil {
		return err
	}
	if digest(original) != expectedSHA256 {
		return ErrConflict
	}
	if digest(candidate) == expectedSHA256 {
		return nil
	}

	staged, err := os.CreateTemp(directory, ".goai-stage-*.tmp")
	if err != nil {
		return err
	}
	stagePath := staged.Name()
	defer os.Remove(stagePath)
	cleanupOpen := func(e error) error { _ = staged.Close(); return e }
	if err := staged.Chmod(originalInfo.Mode().Perm()); err != nil {
		return cleanupOpen(err)
	}
	if st, ok := originalInfo.Sys().(*syscall.Stat_t); ok {
		// Preserve ordinary owner/group metadata. If this is not permitted,
		// fail rather than silently replacing with a differently-owned file.
		if err := staged.Chown(int(st.Uid), int(st.Gid)); err != nil {
			return cleanupOpen(err)
		}
	}
	if _, err := staged.Write(candidate); err != nil {
		return cleanupOpen(err)
	}
	if err := staged.Sync(); err != nil {
		return cleanupOpen(err)
	}
	if err := staged.Close(); err != nil {
		return err
	}
	if beforeFinalCheck != nil {
		if err := beforeFinalCheck(); err != nil {
			return err
		}
	}
	latest, latestInfo, err := current(path)
	if err != nil {
		return err
	}
	if digest(latest) != expectedSHA256 || !os.SameFile(originalInfo, latestInfo) {
		return ErrConflict
	}
	// os.Rename is atomic replacement on the same filesystem, NOT atomic CAS.
	if err := os.Rename(stagePath, path); err != nil {
		return err
	}
	return nil
}

func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func openNoFollow(path string, flags int, mode uint32) (*os.File, error) {
	fd, err := syscall.Open(path, flags|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, mode)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, ErrUnsafeTarget
		}
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func current(path string) ([]byte, os.FileInfo, error) {
	f, err := openNoFollow(path, syscall.O_RDONLY, 0)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, nil, ErrUnsafeTarget
	}
	// Prevent unexpectedly huge source blobs consuming unbounded memory.
	const maxRead = 32 << 20
	if info.Size() > maxRead {
		return nil, nil, fmt.Errorf("source exceeds %d bytes", maxRead)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxRead+1))
	if err != nil {
		return nil, nil, err
	}
	if len(b) > maxRead {
		return nil, nil, fmt.Errorf("source exceeds %d bytes", maxRead)
	}
	return b, info, nil
}
