//go:build linux

package cgroupv2

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func testAuthority(t *testing.T) Authority {
	t.Helper()
	return Authority{
		RequesterUIDs: []uint32{uint32(os.Geteuid())},
		CgroupRoots:   []string{"/sys/fs/cgroup/delegated"},
		TargetDirs:    []string{"/usr/bin"},
		MaxArgv:       8,
	}
}

func writeAuthority(t *testing.T, policy any, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "authority.json")
	raw, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadAuthorityFileRejectsUntrustworthyFiles(t *testing.T) {
	good := testAuthority(t)
	cases := []struct {
		name   string
		policy any
		mode   os.FileMode
	}{
		{"group writable", good, 0664},
		{"world writable", good, 0666},
		{"no requester", Authority{CgroupRoots: good.CgroupRoots, TargetDirs: good.TargetDirs, MaxArgv: 4}, 0600},
		{"no roots", Authority{RequesterUIDs: good.RequesterUIDs, TargetDirs: good.TargetDirs, MaxArgv: 4}, 0600},
		{"no target dirs", Authority{RequesterUIDs: good.RequesterUIDs, CgroupRoots: good.CgroupRoots, MaxArgv: 4}, 0600},
		{"absurd max_argv", Authority{RequesterUIDs: good.RequesterUIDs, CgroupRoots: good.CgroupRoots, TargetDirs: good.TargetDirs, MaxArgv: 99_999}, 0600},
	}
	for _, tc := range cases {
		if _, err := LoadAuthorityFile(writeAuthority(t, tc.policy, tc.mode)); !errors.Is(err, ErrAuthorityUnusable) {
			t.Errorf("%s: accepted (%v)", tc.name, err)
		}
	}
	if _, err := LoadAuthorityFile(""); !errors.Is(err, ErrAuthorityUnusable) {
		t.Error("empty path accepted")
	}
	if _, err := LoadAuthorityFile("relative.json"); !errors.Is(err, ErrAuthorityUnusable) {
		t.Error("relative path accepted")
	}
	if _, err := LoadAuthorityFile(filepath.Join(t.TempDir(), "missing.json")); !errors.Is(err, ErrAuthorityUnusable) {
		t.Error("missing file accepted")
	}
	// Unknown fields are a contract violation, not a comment.
	path := filepath.Join(t.TempDir(), "extra.json")
	raw := []byte(`{"requester_uids":[0],"cgroup_roots":["/a"],"target_dirs":["/b"],"max_argv":4,"allow_anything":true}`)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAuthorityFile(path); !errors.Is(err, ErrAuthorityUnusable) {
		t.Error("unknown policy field accepted")
	}
}

func TestLoadAuthorityAcceptsOwnedPolicy(t *testing.T) {
	path := writeAuthority(t, testAuthority(t), 0600)
	policy, err := LoadAuthorityFile(path)
	if err != nil {
		t.Fatalf("well-formed policy refused: %v", err)
	}
	if len(policy.RequesterUIDs) != 1 || policy.MaxArgv != 8 {
		t.Fatalf("policy not loaded: %+v", policy)
	}
}

func TestAuthorizeRefusesForeignUID(t *testing.T) {
	policy := testAuthority(t)
	stranger := Peer{UID: uint32(os.Geteuid()) + 1, PID: int32(os.Getpid())}
	_, err := policy.Authorize(stranger, Request{
		CgroupPath: "/sys/fs/cgroup/delegated/x", TargetPath: "/usr/bin/true", Argv: []string{"/usr/bin/true"},
	})
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("foreign uid accepted: %v", err)
	}
}

func TestAuthorizeEnforcesPathPolicy(t *testing.T) {
	policy := testAuthority(t)
	peer := Peer{UID: uint32(os.Geteuid()), PID: int32(os.Getpid())}
	bad := []Request{
		// outside the delegated roots
		{CgroupPath: "/sys/fs/cgroup/init.scope/x", TargetPath: "/usr/bin/true", Argv: []string{"/usr/bin/true"}},
		// sibling with a shared prefix is not "inside"
		{CgroupPath: "/sys/fs/cgroup/delegated-evil/x", TargetPath: "/usr/bin/true", Argv: []string{"/usr/bin/true"}},
		// the root itself is not a child group
		{CgroupPath: "/sys/fs/cgroup/delegated", TargetPath: "/usr/bin/true", Argv: []string{"/usr/bin/true"}},
		// relative and unclean paths
		{CgroupPath: "delegated/x", TargetPath: "/usr/bin/true", Argv: []string{"/usr/bin/true"}},
		{CgroupPath: "/sys/fs/cgroup/delegated/../delegated/x", TargetPath: "/usr/bin/true", Argv: []string{"/usr/bin/true"}},
		// target outside the allowlisted directories
		{CgroupPath: "/sys/fs/cgroup/delegated/x", TargetPath: "/bin/sh", Argv: []string{"/bin/sh"}},
		{CgroupPath: "/sys/fs/cgroup/delegated/x", TargetPath: "/usr/bin/../bin/sh", Argv: []string{"/usr/bin/../bin/sh"}},
		// argv[0] must name the target
		{CgroupPath: "/sys/fs/cgroup/delegated/x", TargetPath: "/usr/bin/true", Argv: []string{"/usr/bin/false"}},
		// empty argv
		{CgroupPath: "/sys/fs/cgroup/delegated/x", TargetPath: "/usr/bin/true", Argv: nil},
	}
	for _, request := range bad {
		if _, err := policy.Authorize(peer, request); !errors.Is(err, ErrPolicyDenied) {
			t.Errorf("request %+v accepted: %v", request, err)
		}
	}
}

func TestAuthorizeEnforcesArgvBudget(t *testing.T) {
	policy := testAuthority(t)
	policy.MaxArgv = 2
	peer := Peer{UID: uint32(os.Geteuid()), PID: int32(os.Getpid())}
	request := Request{CgroupPath: "/sys/fs/cgroup/delegated/x", TargetPath: "/usr/bin/true",
		Argv: []string{"/usr/bin/true", "a", "b"}}
	if _, err := policy.Authorize(peer, request); !errors.Is(err, ErrPolicyDenied) {
		t.Fatalf("argv over budget accepted: %v", err)
	}
}

func TestAuthorizeReturnsBoundTicket(t *testing.T) {
	policy := testAuthority(t)
	peer := Peer{UID: uint32(os.Geteuid()), PID: int32(os.Getpid())}
	request := Request{CgroupPath: "/sys/fs/cgroup/delegated/x", TargetPath: "/usr/bin/true",
		Argv: []string{"/usr/bin/true", "--help"}}
	ticket, err := policy.Authorize(peer, request)
	if err != nil {
		t.Fatalf("authorized request refused: %v", err)
	}
	if ticket.CgroupPath() != request.CgroupPath || ticket.TargetPath() != request.TargetPath {
		t.Fatalf("ticket does not bind the request: %+v", ticket)
	}
	// The ticket copies argv: mutating the caller's slice afterwards must not
	// change what will be executed.
	request.Argv[1] = "--evil"
	if ticket.argv[1] != "--help" {
		t.Fatal("ticket aliases caller memory")
	}
}

func TestTicketExecRefusesIncompleteTicket(t *testing.T) {
	for _, ticket := range []Ticket{{}, {cgroup: "/a"}, {cgroup: "/a", target: "/bin/true"}} {
		if err := ticket.Exec(); !errors.Is(err, ErrLaunchDenied) {
			t.Errorf("incomplete ticket executed: %v", err)
		}
	}
}

func TestPeerFromUnixConnReportsKernelIdentity(t *testing.T) {
	fds, err := syscallSocketpair()
	if err != nil {
		t.Skipf("socketpair unavailable: %v", err)
	}
	server := os.NewFile(uintptr(fds[0]), "server")
	client := os.NewFile(uintptr(fds[1]), "client")
	defer server.Close()
	defer client.Close()
	conn, err := net.FileConn(server)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		t.Fatal("not a unix socket")
	}
	peer, err := PeerFromUnixConn(unixConn)
	if err != nil {
		t.Fatalf("peer credentials unavailable: %v", err)
	}
	if peer.UID != uint32(os.Geteuid()) || peer.GID != uint32(os.Getegid()) {
		t.Fatalf("peer identity wrong: %+v", peer)
	}
	if _, err := PeerFromUnixConn(nil); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("nil connection accepted")
	}
}

func TestRequesterExecutableDigestIsChecked(t *testing.T) {
	if os.Getenv("GOAI_EXE_DIGEST_PROBE") != "1" {
		// Without a known digest we can only prove the refusal path: a wrong
		// digest must deny even for an allowed UID.
		policy := testAuthority(t)
		policy.RequesterExeSHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
		peer := Peer{UID: uint32(os.Geteuid()), PID: int32(os.Getpid())}
		_, err := policy.Authorize(peer, Request{CgroupPath: "/sys/fs/cgroup/delegated/x",
			TargetPath: "/usr/bin/true", Argv: []string{"/usr/bin/true"}})
		if !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("wrong executable digest accepted: %v", err)
		}
	}
}

// syscallSocketpair keeps the platform detail in one place.
func syscallSocketpair() ([2]int, error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	return fds, err
}
