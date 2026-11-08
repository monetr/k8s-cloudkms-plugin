// Binary k8s-cloudkms-plugin is the upstream GoogleCloudPlatform/k8s-cloudkms-plugin,
// except that it authenticates to Google Cloud through Workload Identity
// Federation using a JWT signed by a non-exportable key held in the host's TPM,
// instead of a service account key or the GCE metadata server.
//
// Everything below the construction of the HTTP client is identical to the
// upstream main.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/GoogleCloudPlatform/k8s-cloudkms-plugin/plugin"
	v1 "github.com/GoogleCloudPlatform/k8s-cloudkms-plugin/plugin/v1"
	v2 "github.com/GoogleCloudPlatform/k8s-cloudkms-plugin/plugin/v2"
	"github.com/golang/glog"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google/externalaccount"
	"google.golang.org/api/cloudkms/v1"
	"google.golang.org/api/option"

	"github.com/monetr/k8s-cloudkms-plugin/tpmkey"
)

var (
	healthzSocket  = flag.String("healthz-socket", "/var/run/kmsplugin/healthz.sock", "Unix socket on which to publish healthz. Not a TCP port, because each request makes Cloud KMS calls as this node.")
	healthzPath    = flag.String("healthz-path", "healthz", "Path at which to publish healthz")
	healthzTimeout = flag.Duration("healthz-timeout", 5*time.Second, "timeout in seconds for communicating with the unix socket")

	metricsPort = flag.Int("metrics-port", 8082, "Port on localhost on which to publish metrics. 0 disables metrics.")
	metricsPath = flag.String("metrics-path", "metrics", "Path at which to publish metrics")

	keyURI           = flag.String("key-uri", "", "Uri of the key use for crypto operations (ex. projects/my-project/locations/my-location/keyRings/my-key-ring/cryptoKeys/my-key)")
	pathToUnixSocket = flag.String("path-to-unix-socket", "/var/run/kmsplugin/socket.sock", "Full path to Unix socket that is used for communicating with KubeAPI Server, or Linux socket namespace object - must start with @")
	kmsVersion       = flag.String("kms", "v2", "Kubernetes KMS API version. Possible values: v1, v2. Default value is v2.")
	keySuffix        = flag.String("key-suffix", "", "Set to a unique value in case if plugin is reconfigured to use Cloud KMS key version that was already in use before. Applicable only in KMS API v2 mode")

	// TPM / Workload Identity Federation arguments.
	pathToTPM     = flag.String("path-to-tpm", "/dev/tpmrm0", "Path to the TPM resource manager device.")
	tpmKeyHandle  = flag.String("tpm-key-handle", fmt.Sprintf("0x%x", uint32(tpmkey.DefaultHandle)), "Persistent handle of the TPM signing key created by tpm-wif-key. Keys created with the default handle before 1.1.0 are at 0x81010101.")
	wifProvider   = flag.String("wif-provider", "", "Workload identity pool provider resource name (ex. projects/123456789/locations/global/workloadIdentityPools/my-pool/providers/my-provider)")
	jwtIssuer     = flag.String("jwt-issuer", "", "`iss` claim of the signed JWT; must match the provider's --issuer-uri.")
	jwtSubject    = flag.String("jwt-subject", "", "`sub` claim of the signed JWT. Defaults to the hostname.")
	jwtLifetime   = flag.Duration("jwt-lifetime", 5*time.Minute, "Lifetime of each TPM-signed JWT. It is only used for the STS exchange, so keep it short.")
	impersonateSA = flag.String("impersonate-service-account", "", "Optional service account email to impersonate. If empty, the federated identity is used directly and must be granted access to the key.")

	// Boot-state (PCR) binding. These must match how the key was created.
	tpmKeyPCRs      = flag.String("tpm-key-pcrs", "", "Comma-separated PCRs the key was bound to with `tpm-wif-key create -pcrs` (ex. 7). Must match the key.")
	tpmPCRPublicKey = flag.String("tpm-pcr-public-key", "", "PEM RSA public key or certificate the key was bound to with `tpm-wif-key create -pcr-public-key`. Enables signed PCR policies.")
	tpmPCRSignature = flag.String("tpm-pcr-signature", "/run/systemd/tpm2-pcr-signature.json", "Signed PCR policies for the booted UKI. Only used with --tpm-pcr-public-key.")
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	flag.Parse()
	mustValidateFlags()

	// httpClient should be constructed with context.Background. Sending a context with
	// timeout or deadline will cause subsequent calls via the client to fail once the timeout or
	// deadline is triggered. Instead, the plugin supplies a context per individual calls.
	httpClient, err := newTPMHTTPClient(context.Background())
	if err != nil {
		glog.Exitf("failed to instantiate http httpClient: %v", err)
	}

	kms, err := cloudkms.NewService(ctx, option.WithHTTPClient(httpClient))
	if err != nil {
		glog.Exitf("failed to instantiate cloud kms httpClient: %v", err)
	}

	// Metrics are unauthenticated and on TCP, so any local process, including
	// hostNetwork pods, can read them. --metrics-port=0 turns them off.
	var metrics *plugin.Metrics
	if *metricsPort != 0 {
		metrics = &plugin.Metrics{
			ServingURL: &url.URL{
				Host: fmt.Sprintf("localhost:%d", *metricsPort),
				Path: *metricsPath,
			},
		}
	} else {
		glog.Info("Metrics are disabled (--metrics-port=0)")
	}

	var p plugin.Plugin
	var healthChecker plugin.HealthChecker
	switch *kmsVersion {
	case "v1":
		p = v1.NewPlugin(kms.Projects.Locations.KeyRings.CryptoKeys, *keyURI)
		healthChecker = v1.NewHealthChecker()
		glog.Info("Kubernetes KMS API v1beta1")
	case "v2":
		p = v2.NewPlugin(kms.Projects.Locations.KeyRings.CryptoKeys, *keyURI, *keySuffix)
		healthChecker = v2.NewHealthChecker()
		glog.Info("Kubernetes KMS API v2")
	default:
		glog.Exitf("invalid value %q for --kms", *kmsVersion)
	}

	hc := plugin.NewHealthChecker(healthChecker, *keyURI, kms.Projects.Locations.KeyRings.CryptoKeys, *pathToUnixSocket, *healthzTimeout, &url.URL{
		Path: *healthzPath,
	})

	pluginManager := plugin.NewManager(p, *pathToUnixSocket)

	if err := run(pluginManager, hc, metrics, kms.Projects.Locations.KeyRings.CryptoKeys); err != nil {
		glog.Exit(err)
	}
}

// newTPMHTTPClient returns an HTTP client whose access tokens come from an STS
// exchange of a TPM-signed JWT (and optionally a service account
// impersonation). Tokens are cached in memory and refreshed on expiry; nothing
// is written to disk.
func newTPMHTTPClient(ctx context.Context) (*http.Client, error) {
	handle, err := strconv.ParseUint(*tpmKeyHandle, 0, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid --tpm-key-handle %q: %w", *tpmKeyHandle, err)
	}

	subject := *jwtSubject
	if subject == "" {
		if subject, err = os.Hostname(); err != nil {
			return nil, fmt.Errorf("--jwt-subject not set and hostname unavailable: %w", err)
		}
	}

	policy, err := tpmPolicy()
	if err != nil {
		return nil, err
	}
	open := func() (transport.TPMCloser, error) {
		return linuxtpm.Open(*pathToTPM)
	}
	// Turn a mismatched policy or a changed boot state into a clear error,
	// rather than the TPM failure the first signature would give.
	if err := checkTPMPolicy(open, tpm2.TPMHandle(handle), policy); err != nil {
		return nil, err
	}

	conf := externalAccountConfig(open, tpm2.TPMHandle(handle), policy, *tpmPCRSignature, *wifProvider, *jwtIssuer, subject, *jwtLifetime, *impersonateSA)

	ts, client, err := newTokenSourceClient(ctx, conf, googleAPITimeout)
	if err != nil {
		return nil, err
	}

	// Fail fast at startup if the TPM, the JWKS, or the IAM bindings are wrong.
	if _, err := ts.Token(); err != nil {
		return nil, fmt.Errorf("failed to obtain initial access token: %w", err)
	}
	glog.Infof("Authenticated to Google Cloud via %s as subject %q using TPM key 0x%x", *wifProvider, subject, handle)

	return client, nil
}

// googleAPITimeout bounds each HTTP request to Google: the STS exchange, the
// service account impersonation, and each Cloud KMS call.
const googleAPITimeout = 30 * time.Second

// newTokenSourceClient returns the token source for conf and an HTTP client
// that authenticates with it, where every request, including token refreshes,
// is bounded by timeout.
//
// The bound on refreshes matters most. The refresh runs under the token
// source's mutex, and oauth2.Transport doesn't pass the request's context to
// it. Without its own timeout, the STS exchange uses http.DefaultClient, and a
// half-open connection to Google during a refresh would block every Cloud KMS
// call on the node, whatever kube-apiserver's gRPC deadline.
func newTokenSourceClient(
	ctx context.Context,
	conf externalaccount.Config,
	timeout time.Duration,
) (oauth2.TokenSource, *http.Client, error) {
	// externalaccount takes the client for the STS exchange and the
	// impersonation call from this context value.
	ctx = context.WithValue(ctx, oauth2.HTTPClient, &http.Client{Timeout: timeout})

	ts, err := externalaccount.NewTokenSource(ctx, conf)
	if err != nil {
		return nil, nil, err
	}

	// oauth2.NewClient keeps only the context client's Transport, so set the
	// timeout again. Upstream's healthz TestIamPermissions call has no context,
	// so this is its only bound.
	client := oauth2.NewClient(ctx, ts)
	client.Timeout = timeout
	return ts, client, nil
}

// tpmPolicy builds the key's boot-state policy from the --tpm-key-pcrs and
// --tpm-pcr-public-key flags.
func tpmPolicy() (tpmkey.Policy, error) {
	var p tpmkey.Policy
	var err error
	if p.PCRs, err = tpmkey.ParsePCRList(*tpmKeyPCRs); err != nil {
		return p, fmt.Errorf("invalid --tpm-key-pcrs: %w", err)
	}
	if *tpmPCRPublicKey != "" {
		data, err := os.ReadFile(*tpmPCRPublicKey)
		if err != nil {
			return p, fmt.Errorf("failed to read --tpm-pcr-public-key: %w", err)
		}
		if p.PCRSigner, err = tpmkey.ParseRSAPublicKeyPEM(data); err != nil {
			return p, fmt.Errorf("invalid --tpm-pcr-public-key: %w", err)
		}
	}
	return p, nil
}

// checkTPMPolicy checks that the key at handle is bound to exactly policy and
// that the current boot state satisfies it.
func checkTPMPolicy(open func() (transport.TPMCloser, error), handle tpm2.TPMHandle, policy tpmkey.Policy) error {
	var signed []tpmkey.SignedPCRPolicy
	if policy.PCRSigner != nil {
		var err error
		if signed, err = tpmkey.ReadSignedPCRPolicies(*tpmPCRSignature); err != nil {
			return err
		}
	}
	tpm, err := open()
	if err != nil {
		return fmt.Errorf("failed to open TPM: %w", err)
	}
	defer tpm.Close()
	return tpmkey.Check(tpm, handle, policy, signed)
}

// externalAccountConfig describes the STS exchange (and optional service
// account impersonation) for a JWT signed by the TPM key at handle.
func externalAccountConfig(
	open func() (transport.TPMCloser, error),
	handle tpm2.TPMHandle,
	policy tpmkey.Policy,
	signedPCRPolicyPath string,
	provider, issuer, subject string,
	lifetime time.Duration,
	serviceAccount string,
) externalaccount.Config {
	conf := externalaccount.Config{
		// STS wants the provider as a "//iam.googleapis.com/..." resource name...
		Audience:         "//iam.googleapis.com/" + provider,
		SubjectTokenType: "urn:ietf:params:oauth:token-type:jwt",
		Scopes:           []string{cloudkms.CloudPlatformScope},
		SubjectTokenSupplier: &tpmkey.JWTSupplier{
			Open:    open,
			Handle:  handle,
			Issuer:  issuer,
			Subject: subject,
			// ...while the provider's default allowed audience for the JWT is the https form.
			Audience:            "https://iam.googleapis.com/" + provider,
			Lifetime:            lifetime,
			Policy:              policy,
			SignedPCRPolicyPath: signedPCRPolicyPath,
		},
	}
	if serviceAccount != "" {
		conf.ServiceAccountImpersonationURL = fmt.Sprintf(
			"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken", serviceAccount)
	}
	return conf
}

// serveHealthz serves upstream's healthz handler on a unix socket instead of
// upstream's TCP port. Every request makes Cloud KMS calls as this node, so it
// must not be reachable by any local process; a socket keeps it to whoever the
// file mode allows (the service's UMask=0077 makes that root and the plugin).
func serveHealthz(h *plugin.HealthCheckerManager, socketPath, path string) chan error {
	errCh := make(chan error, 1)
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		errCh <- fmt.Errorf("failed to remove stale healthz socket: %w", err)
		return errCh
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		errCh <- fmt.Errorf("failed to listen for healthz: %w", err)
		return errCh
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/"+path, h.HandlerFunc)
	glog.Infof("Registering healthz listener at unix://%s/%s", socketPath, path)
	go func() { errCh <- http.Serve(listener, mux) }()
	return errCh
}

func run(pluginManager *plugin.PluginManager, h *plugin.HealthCheckerManager, m *plugin.Metrics, keys *cloudkms.ProjectsLocationsKeyRingsCryptoKeysService) error {
	signalsChan := make(chan os.Signal, 1)
	signal.Notify(signalsChan, syscall.SIGINT, syscall.SIGTERM)

	// A nil channel never receives, so with metrics disabled that case below
	// never fires.
	var metricsErrCh chan error
	if m != nil {
		metricsErrCh = m.Serve()
	}
	healthzErrCh := serveHealthz(h, *healthzSocket, *healthzPath)

	gRPCSrv, kmsErrorCh := pluginManager.Start()
	if gRPCSrv == nil {
		// Start failed (for example, the socket path isn't writable) and has
		// already sent the reason on the buffered channel. Return it rather
		// than deferring GracefulStop on a nil server, which would panic.
		return <-kmsErrorCh
	}
	defer gRPCSrv.GracefulStop()

	// With Type=notify, systemd only starts units ordered after this one, such
	// as kubelet, once this is sent: the socket is listening, and the initial
	// token fetch has already succeeded.
	if err := sdNotify("READY=1"); err != nil {
		glog.Warningf("Failed to notify systemd of readiness: %v", err)
	}
	if interval := watchdogInterval(); interval > 0 {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		glog.Infof("Pinging the systemd watchdog, interval %v", interval)
		go runWatchdog(ctx, interval, livenessCheck(*pathToUnixSocket, keys, *keyURI))
	}

	for {
		select {
		case sig := <-signalsChan:
			// A requested stop, not a failure: exit 0 so that systemd doesn't
			// mark the unit failed on every stop or restart.
			glog.Infof("captured %v, shutting down kms-plugin", sig)
			return nil
		case kmsError := <-kmsErrorCh:
			return kmsError
		case metricsErr := <-metricsErrCh:
			// Limiting this to warning only - will run without metrics.
			glog.Warning(metricsErr)
			metricsErrCh = nil
		case healthzErr := <-healthzErrCh:
			// Limiting this to warning only - will run without healthz.
			glog.Warning(healthzErr)
			healthzErrCh = nil
		}
	}
}

func mustValidateFlags() {
	if *kmsVersion == "v1" && *keySuffix != "" {
		glog.Exitf("--key-suffix argument cannot be used in v1 mode (--kms=v1)")
	}
	if *wifProvider == "" || *jwtIssuer == "" {
		glog.Exitf("--wif-provider and --jwt-issuer are required")
	}
	glog.Infof("Checking socket path %q", *pathToUnixSocket)
	socketDir := filepath.Dir(*pathToUnixSocket)
	glog.Infof("Unix Socket directory is %q", socketDir)
	if _, err := os.Stat(socketDir); err != nil {
		glog.Exitf(" Directory %q portion of path-to-unix-socket flag:%q does not seem to exist.", socketDir, *pathToUnixSocket)
	}
	glog.Infof("Communication between KUBE API and KMS Plugin containers will be via %q", *pathToUnixSocket)
}
