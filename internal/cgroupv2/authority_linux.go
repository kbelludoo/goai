//go:build linux

package cgroupv2

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

var (
	// ErrUnauthorized means the requesting process is not the supervisor this
	// launcher was installed to serve. Identity comes from the kernel
	// (SO_PEERCRED), not from anything the caller can write.
	ErrUnauthorized = errors.New("GOAI-CGROUP-025: requester identity is not authorized")
	// ErrPolicyDenied means an authorized supervisor asked for something outside
	// the installed policy: a cgroup outside the delegated roots, a target
	// outside the allowed directories, or too many arguments.
	ErrPolicyDenied = errors.New("GOAI-CGROUP-026: request violates the installed launch policy")
	// ErrAuthorityUnusable means the policy file cannot be trusted: wrong owner,
	// writable by group/other, unreadable or malformed.
	ErrAuthorityUnusable = errors.New("GOAI-CGROUP-027: authority policy file is not trustworthy")
)

// Request is what a supervisor asks the launcher to run. It is data, not a
// capability: the launcher re-checks every field against the installed policy.
type Request struct {
	CgroupPath string   `json:"cgroup_path"`
	TargetPath string   `json:"target_path"`
	Argv       []string `json:"argv"`
}

// Peer is the kernel-reported identity of the process at the other end of a
// unix socket. UID cannot be forged by the peer; PID is advisory.
type Peer struct {
	UID uint32
	GID uint32
	PID int32
}

// Authority is the installed policy. It is loaded from a file owned by the
// launcher's effective user with no group/other write, so an unprivileged
// process cannot rewrite the allowlists and then ask for anything it likes.
type Authority struct {
	RequesterUIDs      []uint32 `json:"requester_uids"`
	RequesterExeSHA256 string   `json:"requester_exe_sha256,omitempty"`
	CgroupRoots        []string `json:"cgroup_roots"`
	TargetDirs         []string `json:"target_dirs"`
	MaxArgv            int      `json:"max_argv"`
}

// LoadAuthorityFile reads and validates the policy file.
func LoadAuthorityFile(path string) (Authority, error) {
	var a Authority
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return a, ErrAuthorityUnusable
	}
	info, err := os.Lstat(path)
	if err != nil {
		return a, errors.Join(ErrAuthorityUnusable, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return a, fmt.Errorf("%w: not a regular file", ErrAuthorityUnusable)
	}
	if info.Mode().Perm()&0022 != 0 {
		return a, fmt.Errorf("%w: mode %04o is writable by group or other", ErrAuthorityUnusable, info.Mode().Perm())
	}
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return a, errors.Join(ErrAuthorityUnusable, err)
	}
	if st.Uid != uint32(os.Geteuid()) {
		return a, fmt.Errorf("%w: owned by uid %d, launcher runs as %d", ErrAuthorityUnusable, st.Uid, os.Geteuid())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return a, errors.Join(ErrAuthorityUnusable, err)
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		return a, errors.Join(ErrAuthorityUnusable, err)
	}
	if len(a.RequesterUIDs) == 0 {
		return a, fmt.Errorf("%w: requester_uids is empty", ErrAuthorityUnusable)
	}
	if len(a.CgroupRoots) == 0 || len(a.TargetDirs) == 0 {
		return a, fmt.Errorf("%w: cgroup_roots and target_dirs must be explicit allowlists", ErrAuthorityUnusable)
	}
	if a.MaxArgv <= 0 || a.MaxArgv > 4096 {
		return a, fmt.Errorf("%w: max_argv must be between 1 and 4096", ErrAuthorityUnusable)
	}
	if a.RequesterExeSHA256 != "" {
		sum, err := hex.DecodeString(a.RequesterExeSHA256)
		if err != nil || len(sum) != sha256.Size {
			return a, fmt.Errorf("%w: requester_exe_sha256 must be 64 hex digits", ErrAuthorityUnusable)
		}
	}
	return a, nil
}

// PeerFromUnixConn reads SO_PEERCRED from a connected unix socket.
func PeerFromUnixConn(conn *net.UnixConn) (Peer, error) {
	if conn == nil {
		return Peer{}, ErrUnauthorized
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return Peer{}, errors.Join(ErrUnauthorized, err)
	}
	var peer Peer
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if err != nil {
			credErr = err
			return
		}
		peer = Peer{UID: cred.Uid, GID: cred.Gid, PID: cred.Pid}
	}); err != nil {
		return Peer{}, errors.Join(ErrUnauthorized, err)
	}
	if credErr != nil {
		return Peer{}, errors.Join(ErrUnauthorized, credErr)
	}
	return peer, nil
}

// processExeDigest hashes the executable of a pid. Best-effort hardening on top
// of the UID check: a pid can be recycled between accept and this read, so the
// digest narrows the window but does not replace UID separation.
func processExeDigest(pid int32) (string, error) {
	if pid <= 0 {
		return "", errors.New("no peer pid")
	}
	file, err := os.Open("/proc/" + strconv.Itoa(int(pid)) + "/exe")
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(file, 512<<20)); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// Ticket is an authorized, immutable launch request. Its fields are private and
// it can only be produced by Authorize, so no caller can construct a ticket for
// a cgroup or target that the policy did not approve.
type Ticket struct {
	cgroup  string
	target  string
	argv    []string
	peerUID uint32
}

func (t Ticket) CgroupPath() string { return t.cgroup }
func (t Ticket) TargetPath() string { return t.target }

// Authorize turns a peer + request into a Ticket, or refuses.
func (a Authority) Authorize(peer Peer, req Request) (Ticket, error) {
	allowed := false
	for _, uid := range a.RequesterUIDs {
		if uid == peer.UID {
			allowed = true
			break
		}
	}
	if !allowed {
		return Ticket{}, fmt.Errorf("%w: uid %d", ErrUnauthorized, peer.UID)
	}
	if a.RequesterExeSHA256 != "" {
		digest, err := processExeDigest(peer.PID)
		if err != nil {
			return Ticket{}, errors.Join(ErrUnauthorized, fmt.Errorf("cannot verify requester executable: %w", err))
		}
		if digest != a.RequesterExeSHA256 {
			return Ticket{}, fmt.Errorf("%w: requester executable digest mismatch", ErrUnauthorized)
		}
	}
	if len(req.Argv) == 0 || len(req.Argv) > a.MaxArgv {
		return Ticket{}, fmt.Errorf("%w: argc %d outside 1..%d", ErrPolicyDenied, len(req.Argv), a.MaxArgv)
	}
	if err := requireUnder(req.CgroupPath, a.CgroupRoots, "cgroup"); err != nil {
		return Ticket{}, err
	}
	if err := requireUnder(req.TargetPath, a.TargetDirs, "target"); err != nil {
		return Ticket{}, err
	}
	if req.Argv[0] != req.TargetPath {
		return Ticket{}, fmt.Errorf("%w: argv[0] must equal target_path", ErrPolicyDenied)
	}
	for _, arg := range req.Argv {
		if strings.IndexByte(arg, 0) >= 0 {
			return Ticket{}, fmt.Errorf("%w: argument contains NUL", ErrPolicyDenied)
		}
	}
	return Ticket{cgroup: req.CgroupPath, target: req.TargetPath, argv: append([]string{}, req.Argv...), peerUID: peer.UID}, nil
}

// requireUnder accepts only absolute, clean paths strictly inside one of the
// allowlisted directories, compared component-wise (`/a/bc` is not under `/a/b`).
func requireUnder(path string, roots []string, kind string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("%w: %s path must be absolute and clean", ErrPolicyDenied, kind)
	}
	for _, root := range roots {
		if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
			continue
		}
		relative, err := filepath.Rel(root, path)
		if err != nil || relative == "." || relative == ".." ||
			strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			continue
		}
		return nil
	}
	return fmt.Errorf("%w: %s %q is not inside an allowlisted directory", ErrPolicyDenied, kind, path)
}

// Exec launches the authorized request. It re-validates the ticket's own fields
// and then runs the same fail-closed sequence as the direct launcher:
// check -> self-migration -> pin executable -> scrub descriptors -> execveat.
// On success it does not return.
func (t Ticket) Exec() error {
	if t.cgroup == "" || t.target == "" || len(t.argv) == 0 {
		return ErrLaunchDenied
	}
	return execPrepared(t.cgroup, t.target, t.argv)
}
