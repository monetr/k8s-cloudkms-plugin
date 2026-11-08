package main

import (
	"context"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/GoogleCloudPlatform/k8s-cloudkms-plugin/plugin"
	v2 "github.com/GoogleCloudPlatform/k8s-cloudkms-plugin/plugin/v2"
	"google.golang.org/api/cloudkms/v1"
)

// errSignal stands in for the cause signal.NotifyContext cancels with.
var errSignal = errors.New("terminated signal received")

// startRun calls run in the background with sockets under a temporary
// directory, and returns its config and a channel with run's result. The
// plugin has no Cloud KMS client, so only the watchdog may call Cloud KMS,
// through keys.
func startRun(
	t *testing.T,
	ctx context.Context,
	kmsSocket string,
	keys *cloudkms.ProjectsLocationsKeyRingsCryptoKeysService,
) (runConfig, <-chan error) {
	t.Helper()
	cfg := runConfig{
		healthzSocket: filepath.Join(t.TempDir(), "healthz.sock"),
		healthzPath:   "healthz",
		kmsSocket:     kmsSocket,
		keyURI:        testKeyURI,
	}
	p := v2.NewPlugin(nil, cfg.keyURI, "")
	hc := plugin.NewHealthChecker(v2.NewHealthChecker(), cfg.keyURI, nil, kmsSocket, time.Second, &url.URL{Path: cfg.healthzPath})
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfg, plugin.NewManager(p, kmsSocket), hc, nil, keys) }()
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

func nextMessage(t *testing.T, msgs <-chan string) string {
	t.Helper()
	select {
	case m := <-msgs:
		return m
	case <-time.After(5 * time.Second):
		t.Fatal("nothing received")
		return ""
	}
}

// expectNoMessage must be called after run has returned, so that anything it
// sent is already in the socket's buffer.
func expectNoMessage(t *testing.T, msgs <-chan string) {
	t.Helper()
	select {
	case m := <-msgs:
		t.Fatalf("unexpected message %q", m)
	case <-time.After(100 * time.Millisecond):
	}
}

// A stop is not a failure: run must return nil, so the plugin exits 0 and
// systemd doesn't mark the unit failed on every stop or restart.
func TestRunStopsWhenCancelled(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	kmsSocket := filepath.Join(t.TempDir(), "kms.sock")
	cfg, done := startRun(t, ctx, kmsSocket, nil)
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
	cfg, done := startRun(t, ctx, kmsSocket, nil)

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
	_, done := startRun(t, context.Background(), kmsSocket, nil)

	err := waitForResult(t, done)
	if err == nil || !strings.Contains(err.Error(), "failed to create listener") {
		t.Fatalf("run returned %v, want a listener error", err)
	}
}

// systemd starts units ordered after the plugin, such as kubelet, when it gets
// READY=1, so by then the socket must accept connections.
func TestRunNotifiesReadyWhenServing(t *testing.T) {
	t.Setenv("WATCHDOG_USEC", "")
	msgs := listenNotify(t, filepath.Join(t.TempDir(), "notify"))
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	kmsSocket := filepath.Join(t.TempDir(), "kms.sock")
	_, done := startRun(t, ctx, kmsSocket, nil)

	if got := nextMessage(t, msgs); got != "READY=1" {
		t.Fatalf("got %q, want READY=1", got)
	}
	conn, err := net.Dial("unix", kmsSocket)
	if err != nil {
		t.Fatalf("socket not accepting connections after READY=1: %v", err)
	}
	conn.Close()

	cancel(errSignal)
	if err := waitForResult(t, done); err != nil {
		t.Fatalf("run returned %v, want nil", err)
	}
	expectNoMessage(t, msgs)
}

// A false READY=1 would start kubelet against a plugin that isn't there.
func TestRunNotReadyWhenNotServing(t *testing.T) {
	cancelled, cancel := context.WithCancelCause(context.Background())
	cancel(errSignal)
	dir := t.TempDir()
	for name, tc := range map[string]struct {
		ctx       context.Context
		kmsSocket string
	}{
		"signal during startup":   {cancelled, filepath.Join(dir, "kms.sock")},
		"socket can't be created": {context.Background(), filepath.Join(dir, "missing", "kms.sock")},
	} {
		t.Run(name, func(t *testing.T) {
			msgs := listenNotify(t, filepath.Join(t.TempDir(), "notify"))
			_, done := startRun(t, tc.ctx, tc.kmsSocket, nil)
			waitForResult(t, done)
			expectNoMessage(t, msgs)
		})
	}
}

// The watchdog's checks run against the real gRPC server here, so this also
// covers that the server answers the probe with Unimplemented.
func TestRunStartsWatchdog(t *testing.T) {
	const interval = 400 * time.Millisecond
	t.Setenv("WATCHDOG_USEC", strconv.FormatInt(interval.Microseconds(), 10))
	t.Setenv("WATCHDOG_PID", "")
	msgs := listenNotify(t, filepath.Join(t.TempDir(), "notify"))
	keys := fakeKMS(t, permissions(
		"cloudkms.cryptoKeyVersions.useToEncrypt",
		"cloudkms.cryptoKeyVersions.useToDecrypt",
	))
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	_, done := startRun(t, ctx, filepath.Join(t.TempDir(), "kms.sock"), keys)

	if got := nextMessage(t, msgs); got != "READY=1" {
		t.Fatalf("got %q, want READY=1 first", got)
	}
	if got := nextMessage(t, msgs); got != "WATCHDOG=1" {
		t.Fatalf("got %q, want WATCHDOG=1", got)
	}

	cancel(errSignal)
	if err := waitForResult(t, done); err != nil {
		t.Fatalf("run returned %v, want nil", err)
	}
}
