package main

import (
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GoogleCloudPlatform/k8s-cloudkms-plugin/plugin"
	v2 "github.com/GoogleCloudPlatform/k8s-cloudkms-plugin/plugin/v2"
)

// errSignal stands in for the cause signal.NotifyContext cancels with.
var errSignal = errors.New("terminated signal received")

// startRun calls run in the background with sockets under a temporary
// directory, and returns its config and a channel with run's result. The
// plugin has no Cloud KMS client, so nothing here may call Cloud KMS.
func startRun(t *testing.T, ctx context.Context, kmsSocket string) (runConfig, <-chan error) {
	t.Helper()
	cfg := runConfig{
		healthzSocket: filepath.Join(t.TempDir(), "healthz.sock"),
		healthzPath:   "healthz",
		kmsSocket:     kmsSocket,
		keyURI:        "projects/p/locations/l/keyRings/r/cryptoKeys/k",
	}
	p := v2.NewPlugin(nil, cfg.keyURI, "")
	hc := plugin.NewHealthChecker(v2.NewHealthChecker(), cfg.keyURI, nil, kmsSocket, time.Second, &url.URL{Path: cfg.healthzPath})
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfg, plugin.NewManager(p, kmsSocket), hc, nil, nil) }()
	return cfg, done
}

func waitForSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s was never created", path)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitForResult(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return")
		return nil
	}
}

// A stop is not a failure: run must return nil, so the plugin exits 0 and
// systemd doesn't mark the unit failed on every stop or restart.
func TestRunStopsWhenCancelled(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	kmsSocket := filepath.Join(t.TempDir(), "kms.sock")
	cfg, done := startRun(t, ctx, kmsSocket)
	waitForSocket(t, kmsSocket)
	waitForSocket(t, cfg.healthzSocket)

	cancel(errSignal)
	if err := waitForResult(t, done); err != nil {
		t.Fatalf("run returned %v, want nil", err)
	}
}

// A signal during startup cancels ctx before run is called. run must exit
// without serving, rather than lose the signal and keep running until systemd
// SIGKILLs it.
func TestRunExitsOnSignalDuringStartup(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(errSignal)
	kmsSocket := filepath.Join(t.TempDir(), "kms.sock")
	cfg, done := startRun(t, ctx, kmsSocket)

	if err := waitForResult(t, done); err != nil {
		t.Fatalf("run returned %v, want nil", err)
	}
	for _, path := range []string{kmsSocket, cfg.healthzSocket} {
		if _, err := os.Stat(path); err == nil {
			t.Errorf("%s was created after a signal during startup", path)
		}
	}
}

// When the gRPC server can't start, run must return the reason instead of
// panicking on the nil server.
func TestRunReturnsStartError(t *testing.T) {
	kmsSocket := filepath.Join(t.TempDir(), "missing", "kms.sock")
	_, done := startRun(t, context.Background(), kmsSocket)

	err := waitForResult(t, done)
	if err == nil || !strings.Contains(err.Error(), "failed to create listener") {
		t.Fatalf("run returned %v, want a listener error", err)
	}
}
