package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/api/cloudkms/v1"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
)

// listenNotify points NOTIFY_SOCKET at a datagram socket at path (a file, or
// "@name" for an abstract socket) and returns the messages sent to it.
func listenNotify(t *testing.T, path string) <-chan string {
	t.Helper()
	l, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	t.Setenv("NOTIFY_SOCKET", path)

	msgs := make(chan string, 100)
	go func() {
		buf := make([]byte, 256)
		for {
			n, err := l.Read(buf)
			if err != nil {
				return
			}
			msgs <- string(buf[:n])
		}
	}()
	return msgs
}

func abstractName(t *testing.T) string {
	return fmt.Sprintf("@k8s-cloudkms-plugin-test-%d-%s", os.Getpid(), t.Name())
}

func TestSdNotify(t *testing.T) {
	t.Run("not under systemd", func(t *testing.T) {
		t.Setenv("NOTIFY_SOCKET", "")
		if err := sdNotify("READY=1"); err != nil {
			t.Fatalf("expected nothing to happen, got %v", err)
		}
	})
	for name, path := range map[string]string{
		"socket file":     filepath.Join(t.TempDir(), "notify"),
		"abstract socket": abstractName(t),
	} {
		t.Run(name, func(t *testing.T) {
			msgs := listenNotify(t, path)
			if err := sdNotify("READY=1"); err != nil {
				t.Fatal(err)
			}
			select {
			case got := <-msgs:
				if got != "READY=1" {
					t.Fatalf("got %q, want READY=1", got)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("nothing received")
			}
		})
	}
	t.Run("socket missing", func(t *testing.T) {
		t.Setenv("NOTIFY_SOCKET", filepath.Join(t.TempDir(), "missing"))
		if err := sdNotify("READY=1"); err == nil {
			t.Fatal("expected an error")
		}
	})
}

func TestWatchdogInterval(t *testing.T) {
	self := strconv.Itoa(os.Getpid())
	for _, tc := range []struct {
		name, usec, pid string
		want            time.Duration
	}{
		{"off", "", "", 0},
		{"set", "2000000", "", 2 * time.Second},
		{"for this process", "2000000", self, 2 * time.Second},
		// systemd only sets WATCHDOG_PID for the main process; a child that
		// inherited the variables must not ping.
		{"for another process", "2000000", "1", 0},
		{"not a number", "two seconds", "", 0},
		{"zero", "0", "", 0},
		{"negative", "-5", "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("WATCHDOG_USEC", tc.usec)
			t.Setenv("WATCHDOG_PID", tc.pid)
			if got := watchdogInterval(); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// countPings runs runWatchdog with check for d and returns how many pings
// systemd would have received.
func countPings(t *testing.T, interval, d time.Duration, check func(context.Context) error) int {
	t.Helper()
	msgs := listenNotify(t, filepath.Join(t.TempDir(), "notify"))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runWatchdog(ctx, interval, check)
		close(done)
	}()
	time.Sleep(d)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runWatchdog didn't return after its context was cancelled")
	}

	pings := 0
	for {
		select {
		case m := <-msgs:
			if m != "WATCHDOG=1" {
				t.Fatalf("unexpected message %q", m)
			}
			pings++
		case <-time.After(100 * time.Millisecond):
			return pings
		}
	}
}

func TestRunWatchdog(t *testing.T) {
	const interval = 100 * time.Millisecond

	t.Run("pings while the check passes", func(t *testing.T) {
		var checks atomic.Int32
		pings := countPings(t, interval, time.Second, func(ctx context.Context) error {
			checks.Add(1)
			// Each check gets half the interval.
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) > interval/2 {
				t.Errorf("check deadline %v, want at most %v from now", time.Until(deadline), interval/2)
			}
			return nil
		})
		// About one check every quarter interval; allow for a slow machine. The
		// last check may finish as the context is cancelled, and then not ping.
		if n := int(checks.Load()); pings < 3 || pings > n || pings < n-1 {
			t.Fatalf("got %d pings for %d checks, want one per check and at least 3", pings, n)
		}
	})

	t.Run("withholds pings while the check fails", func(t *testing.T) {
		pings := countPings(t, interval, 500*time.Millisecond, func(context.Context) error {
			return fmt.Errorf("stuck")
		})
		if pings != 0 {
			t.Fatalf("got %d pings, want none", pings)
		}
	})
}

// serveGRPC starts a gRPC server with no services on a unix socket at path,
// like the plugin's from the watchdog's point of view: it answers any call it
// doesn't implement with Unimplemented.
func serveGRPC(t *testing.T, path string) {
	t.Helper()
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	go srv.Serve(l)
	t.Cleanup(srv.Stop)
}

// fakeKMS serves TestIamPermissions. respond decides each answer; a nil
// respond hangs until the test ends.
func fakeKMS(t *testing.T, respond func(w http.ResponseWriter)) *cloudkms.ProjectsLocationsKeyRingsCryptoKeysService {
	t.Helper()
	// An explicit channel, because the server only notices a client going away
	// once the request body has been read, so r.Context() wouldn't end here.
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, ":testIamPermissions") {
			t.Errorf("unexpected Cloud KMS call %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if respond == nil {
			<-release
			return
		}
		respond(w)
	}))
	// Cleanups run last first: release the handler, then close the server,
	// which waits for it.
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })
	kms, err := cloudkms.NewService(context.Background(), option.WithEndpoint(srv.URL), option.WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatal(err)
	}
	return kms.Projects.Locations.KeyRings.CryptoKeys
}

func permissions(perms ...string) func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		fmt.Fprintf(w, `{"permissions":[%s]}`, `"`+strings.Join(perms, `","`)+`"`)
	}
}

const testKeyURI = "projects/p/locations/l/keyRings/r/cryptoKeys/k"

func TestLivenessCheck(t *testing.T) {
	const (
		encrypt = "cloudkms.cryptoKeyVersions.useToEncrypt"
		decrypt = "cloudkms.cryptoKeyVersions.useToDecrypt"
	)
	// Every one of these means Cloud KMS answered, so the plugin isn't
	// wedged. A restart wouldn't fix any of them.
	alive := map[string]func(w http.ResponseWriter){
		"permission granted": permissions(encrypt, decrypt),
		"permission missing": permissions(encrypt),
		"permission denied": func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"error":{"code":403,"message":"denied"}}`)
		},
		"outage": func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, `{"error":{"code":503,"message":"unavailable"}}`)
		},
	}
	for name, respond := range alive {
		t.Run(name, func(t *testing.T) {
			socket := filepath.Join(t.TempDir(), "kms.sock")
			serveGRPC(t, socket)
			check := livenessCheck(socket, fakeKMS(t, respond), testKeyURI)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := check(ctx); err != nil {
				t.Fatalf("expected the check to pass, got %v", err)
			}
		})
	}

	t.Run("abstract socket", func(t *testing.T) {
		socket := abstractName(t)
		serveGRPC(t, socket)
		check := livenessCheck(socket, fakeKMS(t, permissions(encrypt, decrypt)), testKeyURI)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := check(ctx); err != nil {
			t.Fatalf("expected the check to pass, got %v", err)
		}
	})

	t.Run("Cloud KMS call hangs", func(t *testing.T) {
		socket := filepath.Join(t.TempDir(), "kms.sock")
		serveGRPC(t, socket)
		check := livenessCheck(socket, fakeKMS(t, nil), testKeyURI)
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		if err := check(ctx); err == nil || !strings.Contains(err.Error(), "stuck") {
			t.Fatalf("expected the check to fail as stuck, got %v", err)
		}
	})

	t.Run("gRPC server not answering", func(t *testing.T) {
		socket := filepath.Join(t.TempDir(), "kms.sock") // nothing listens here
		check := livenessCheck(socket, fakeKMS(t, permissions(encrypt, decrypt)), testKeyURI)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := check(ctx); err == nil || !strings.Contains(err.Error(), "didn't answer") {
			t.Fatalf("expected the check to fail, got %v", err)
		}
	})
}

func TestMissingPermissions(t *testing.T) {
	want := []string{"a", "b"}
	for _, tc := range []struct {
		got, missing []string
	}{
		{[]string{"a", "b"}, nil},
		{[]string{"b", "a", "c"}, nil},
		{[]string{"a"}, []string{"b"}},
		{nil, []string{"a", "b"}},
	} {
		if got := missingPermissions(want, tc.got); !slices.Equal(got, tc.missing) {
			t.Errorf("missingPermissions(%v, %v) = %v, want %v", want, tc.got, got, tc.missing)
		}
	}
}
