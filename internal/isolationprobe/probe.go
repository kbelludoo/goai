// Package isolationprobe contains the trusted, read-only isolation canaries.
// The helper must be built by the trusted GoAI operator, not supplied by an AI.
package isolationprobe

import (
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

// Observation is measured inside the child process, never submitted by an agent.
type Observation struct {
	HostReachable    bool   `json:"host_reachable"`
	SentinelReadable bool   `json:"sentinel_readable"`
	NetNamespace     string `json:"net_namespace"`
	MountNamespace   string `json:"mount_namespace"`
	PIDNamespace     string `json:"pid_namespace"`
}

// Run attempts to access two known host-owned resources and reads kernel
// namespace identities from /proc. A failed connection by itself is not a
// proof of isolation; the host also verifies the namespace identities.
func Run(hostURL, sentinelPath string) (Observation, error) {
	if hostURL == "" || sentinelPath == "" {
		return Observation{}, errors.New("missing trusted canary inputs")
	}
	netNS, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return Observation{}, err
	}
	mntNS, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil {
		return Observation{}, err
	}
	pidNS, err := os.Readlink("/proc/self/ns/pid")
	if err != nil {
		return Observation{}, err
	}
	// Disable proxy lookup, including inherited HTTP_PROXY. No credentials.
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{
		Proxy: nil, DialContext: (&net.Dialer{Timeout: time.Second}).DialContext,
	}}
	resp, networkErr := client.Get(hostURL)
	if networkErr == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 2048))
		_ = resp.Body.Close()
	}
	_, fsErr := os.ReadFile(sentinelPath)
	return Observation{
		HostReachable: networkErr == nil, SentinelReadable: fsErr == nil,
		NetNamespace: netNS, MountNamespace: mntNS, PIDNamespace: pidNS,
	}, nil
}
