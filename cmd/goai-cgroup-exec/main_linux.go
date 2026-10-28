//go:build linux

// goai-cgroup-exec is a trusted internal launcher, not an agent-facing tool.
//
// It accepts a launch request only from the supervisor named in its installed
// policy, verifies that identity with the kernel (SO_PEERCRED on an inherited
// unix socket), checks the request against the policy, migrates itself into the
// prepared cgroup, and execs the pinned executable. A caller cannot pass a
// cgroup path or an executable path by argument: those are policy outcomes.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/kbelludoo/goai/internal/cgroupv2"
)

const maxRequestBytes = 64 << 10

func main() {
	authorityPath := os.Getenv("GOAI_AUTHORITY_CONFIG")
	if len(os.Args) > 2 && os.Args[1] == "-authority" {
		authorityPath = os.Args[2]
	}
	authority, err := cgroupv2.LoadAuthorityFile(authorityPath)
	if err != nil {
		fail("authority", err)
	}
	ticket, err := authorizeRequest(authority)
	if err != nil {
		fail("authorize", err)
	}
	// On success the process image is replaced; nothing below runs.
	err = ticket.Exec()
	fail("exec", err)
}

// authorizeRequest reads exactly one bounded request from the supervisor socket
// inherited as fd 3 and turns it into a Ticket.
func authorizeRequest(authority cgroupv2.Authority) (cgroupv2.Ticket, error) {
	file := os.NewFile(3, "supervisor")
	if file == nil {
		return cgroupv2.Ticket{}, errors.New("supervisor socket missing (expected fd 3)")
	}
	conn, err := net.FileConn(file)
	if err != nil {
		return cgroupv2.Ticket{}, fmt.Errorf("supervisor socket: %w", err)
	}
	defer conn.Close()
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return cgroupv2.Ticket{}, errors.New("supervisor channel must be a unix socket")
	}
	peer, err := cgroupv2.PeerFromUnixConn(unixConn)
	if err != nil {
		return cgroupv2.Ticket{}, err
	}
	var request cgroupv2.Request
	dec := json.NewDecoder(io.LimitReader(conn, maxRequestBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&request); err != nil {
		return cgroupv2.Ticket{}, fmt.Errorf("request: %w", err)
	}
	return authority.Authorize(peer, request)
}

// fail is fail-closed: no workload runs after any error.
func fail(stage string, err error) {
	fmt.Fprintln(os.Stderr, "goai-cgroup-exec:", stage+":", err)
	switch {
	case errors.Is(err, cgroupv2.ErrUnauthorized):
		os.Exit(125)
	case errors.Is(err, cgroupv2.ErrLaunchDenied),
		errors.Is(err, cgroupv2.ErrJoinFailed),
		errors.Is(err, cgroupv2.ErrNotExclusive),
		errors.Is(err, cgroupv2.ErrGroupNotOwned),
		errors.Is(err, cgroupv2.ErrPolicyDenied),
		errors.Is(err, cgroupv2.ErrAuthorityUnusable),
		errors.Is(err, cgroupv2.ErrExecutableChanged):
		os.Exit(126)
	}
	os.Exit(127)
}
