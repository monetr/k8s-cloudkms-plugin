package main

// Readiness and watchdog notifications to systemd, using the sd_notify
// protocol: one datagram per message to the unix socket named by
// $NOTIFY_SOCKET. Everything here does nothing when the plugin isn't run by
// systemd with Type=notify (and, for the watchdog, WatchdogSec=).

import (
	"context"
	"fmt"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/golang/glog"
	"google.golang.org/api/cloudkms/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

// sdNotify sends state, for example "READY=1", to systemd. A $NOTIFY_SOCKET
// starting with "@" is an abstract socket, which net handles.
func sdNotify(state string) error {
	path := os.Getenv("NOTIFY_SOCKET")
	if path == "" {
		return nil
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte(state))
	return err
}

// watchdogInterval returns systemd's watchdog interval for this process, or 0
// if the watchdog is off.
func watchdogInterval() time.Duration {
	usec, err := strconv.ParseInt(os.Getenv("WATCHDOG_USEC"), 10, 64)
	if err != nil || usec <= 0 {
		return 0
	}
	if pid := os.Getenv("WATCHDOG_PID"); pid != "" && pid != strconv.Itoa(os.Getpid()) {
		return 0
	}
	return time.Duration(usec) * time.Microsecond
}

// runWatchdog pings systemd's watchdog each time check succeeds, until ctx is
// done. Each check gets half the interval, with a quarter of the interval
// between checks, so a slow check that still succeeds pings at least every
// three quarters of the interval. A check that fails or doesn't finish in time
// withholds the ping. If that lasts the whole interval, systemd kills the
// plugin with SIGABRT, which makes Go write every goroutine's stack to the
// journal, and Restart= starts it again.
func runWatchdog(ctx context.Context, interval time.Duration, check func(context.Context) error) {
	for {
		checkCtx, cancel := context.WithTimeout(ctx, interval/2)
		err := check(checkCtx)
		cancel()
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			glog.Warningf("Watchdog check failed, not pinging systemd: %v", err)
		} else if err := sdNotify("WATCHDOG=1"); err != nil {
			glog.Warningf("Failed to ping the systemd watchdog: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval / 4):
		}
	}
}

// livenessCheck returns a check that fails if the plugin is wedged, not if
// Google is unreachable. A restart can't fix a Cloud KMS or STS outage, and
// the restarted plugin would fail its startup token fetch and stay down. It
// checks:
//
//   - The gRPC server on socketPath. It's asked for a method it doesn't
//     implement, and answering Unimplemented proves it accepts connections and
//     dispatches calls.
//   - The path every Encrypt and Decrypt takes to Cloud KMS: the token source
//     (a refresh holds its mutex, so one that hangs blocks every request), the
//     TPM, STS, and the HTTP client. It asks Cloud KMS whether this node still
//     has encrypt and decrypt permission on the key, rather than calling the
//     KMS Status method, which does a real Encrypt. TestIamPermissions isn't a
//     cryptographic operation, and it doesn't touch the plugin's metrics or the
//     key ID it reports.
//
// The answer only matters for logging: a lost permission or an outage is
// logged when it starts and when it ends, but still counts as alive. Only a
// call that doesn't return in time fails the check. If one is stuck, the
// goroutine running it leaks until the watchdog kills the process.
func livenessCheck(
	socketPath string,
	keys *cloudkms.ProjectsLocationsKeyRingsCryptoKeysService,
	keyURI string,
) func(context.Context) error {
	target := "unix:" + socketPath
	if strings.HasPrefix(socketPath, "@") {
		target = "unix-abstract:" + socketPath[1:]
	}
	// Checks run one at a time, so this needs no lock.
	var lastProblem string

	return func(ctx context.Context) error {
		conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return err
		}
		defer conn.Close()
		_, err = healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
		if err != nil && status.Code(err) != codes.Unimplemented {
			return fmt.Errorf("gRPC server on %s didn't answer: %w", socketPath, err)
		}

		type result struct {
			resp *cloudkms.TestIamPermissionsResponse
			err  error
		}
		done := make(chan result, 1)
		go func() {
			resp, err := keys.TestIamPermissions(keyURI, &cloudkms.TestIamPermissionsRequest{Permissions: keyPermissions}).Context(ctx).Do()
			done <- result{resp, err}
		}()
		var r result
		select {
		case r = <-done:
		case <-ctx.Done():
		}
		if ctx.Err() != nil {
			return fmt.Errorf("checking access to Cloud KMS is stuck: %w", ctx.Err())
		}

		problem := ""
		if r.err != nil {
			problem = fmt.Sprintf("failed to check permissions on %s: %v", keyURI, r.err)
		} else if missing := missingPermissions(keyPermissions, r.resp.Permissions); len(missing) > 0 {
			problem = fmt.Sprintf("missing %v on %s", missing, keyURI)
		}
		if problem != lastProblem {
			if problem != "" {
				glog.Warningf("Cloud KMS access check: %s", problem)
			} else {
				glog.Infof("Cloud KMS access check: encrypt and decrypt permission on %s is back", keyURI)
			}
			lastProblem = problem
		}
		return nil
	}
}

// keyPermissions are what the plugin needs on the key, the same permissions
// upstream's healthz checks.
var keyPermissions = []string{"cloudkms.cryptoKeyVersions.useToDecrypt", "cloudkms.cryptoKeyVersions.useToEncrypt"}

func missingPermissions(want, got []string) []string {
	var missing []string
	for _, w := range want {
		if !slices.Contains(got, w) {
			missing = append(missing, w)
		}
	}
	return missing
}
