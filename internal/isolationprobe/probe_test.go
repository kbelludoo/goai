package isolationprobe

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestPositiveHostControlsDetectAccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("HOST_REACHABLE")) }))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "host-sentinel")
	if err := os.WriteFile(path, []byte("SECRET"), 0600); err != nil {
		t.Fatal(err)
	}
	observed, err := Run(server.URL, path)
	if err != nil {
		t.Fatal(err)
	}
	if !observed.HostReachable || !observed.SentinelReadable {
		t.Fatalf("positive controls failed: %+v", observed)
	}
	if observed.NetNamespace == "" || observed.MountNamespace == "" || observed.PIDNamespace == "" {
		t.Fatalf("missing kernel namespace identities: %+v", observed)
	}
}
func TestMissingInputsRejected(t *testing.T) {
	if _, err := Run("", ""); err == nil {
		t.Fatal("missing inputs accepted")
	}
}
