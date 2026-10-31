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
	healthzPort    = flag.Int("healthz-port", 8081, "Port on which to publish healthz")
	healthzPath    = flag.String("healthz-path", "healthz", "Path at which to publish healthz")
	healthzTimeout = flag.Duration("healthz-timeout", 5*time.Second, "timeout in seconds for communicating with the unix socket")

	metricsPort = flag.Int("metrics-port", 8082, "Port on which to publish metrics")
	metricsPath = flag.String("metrics-path", "metrics", "Path at which to publish metrics")

	keyURI           = flag.String("key-uri", "", "Uri of the key use for crypto operations (ex. projects/my-project/locations/my-location/keyRings/my-key-ring/cryptoKeys/my-key)")
	pathToUnixSocket = flag.String("path-to-unix-socket", "/var/run/kmsplugin/socket.sock", "Full path to Unix socket that is used for communicating with KubeAPI Server, or Linux socket namespace object - must start with @")
	kmsVersion       = flag.String("kms", "v2", "Kubernetes KMS API version. Possible values: v1, v2. Default value is v2.")
	keySuffix        = flag.String("key-suffix", "", "Set to a unique value in case if plugin is reconfigured to use Cloud KMS key version that was already in use before. Applicable only in KMS API v2 mode")

	// TPM / Workload Identity Federation arguments.
	pathToTPM     = flag.String("path-to-tpm", "/dev/tpmrm0", "Path to the TPM resource manager device.")
	tpmKeyHandle  = flag.String("tpm-key-handle", fmt.Sprintf("0x%x", uint32(tpmkey.DefaultHandle)), "Persistent handle of the TPM signing key created by tpm-wif-key.")
	wifProvider   = flag.String("wif-provider", "", "Workload identity pool provider resource name (ex. projects/123456789/locations/global/workloadIdentityPools/my-pool/providers/my-provider)")
	jwtIssuer     = flag.String("jwt-issuer", "", "`iss` claim of the signed JWT; must match the provider's --issuer-uri.")
	jwtSubject    = flag.String("jwt-subject", "", "`sub` claim of the signed JWT. Defaults to the hostname.")
	jwtLifetime   = flag.Duration("jwt-lifetime", 5*time.Minute, "Lifetime of each TPM-signed JWT. It is only used for the STS exchange, so keep it short.")
	impersonateSA = flag.String("impersonate-service-account", "", "Optional service account email to impersonate. If empty, the federated identity is used directly and must be granted access to the key.")

	// Integration testing arguments.
	integrationTest = flag.Bool("integration-test", false, "When set to true, http.DefaultClient will be used, as opposed callers identity acquired with a TokenService.")
	fakeKMSPort     = flag.Int("fake-kms-port", 8085, "Port for Fake KMS, only use in integration tests.")
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	flag.Parse()
	mustValidateFlags()

	var (
		httpClient = http.DefaultClient
		err        error
	)

	if !*integrationTest {
		// httpClient should be constructed with context.Background. Sending a context with
		// timeout or deadline will cause subsequent calls via the client to fail once the timeout or
		// deadline is triggered. Instead, the plugin supplies a context per individual calls.
		httpClient, err = newTPMHTTPClient(context.Background())
		if err != nil {
			glog.Exitf("failed to instantiate http httpClient: %v", err)
		}
	}

	kms, err := cloudkms.NewService(ctx, option.WithHTTPClient(httpClient))
	if err != nil {
		glog.Exitf("failed to instantiate cloud kms httpClient: %v", err)
	}

	if *integrationTest {
		kms.BasePath = fmt.Sprintf("http://localhost:%d", *fakeKMSPort)
	}

	metrics := &plugin.Metrics{
		ServingURL: &url.URL{
			Host: fmt.Sprintf("localhost:%d", *metricsPort),
			Path: *metricsPath,
		},
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
		Host: fmt.Sprintf("localhost:%d", *healthzPort),
		Path: *healthzPath,
	})

	pluginManager := plugin.NewManager(p, *pathToUnixSocket)

	glog.Exit(run(pluginManager, hc, metrics))
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

	conf := externalAccountConfig(func() (transport.TPMCloser, error) {
		return linuxtpm.Open(*pathToTPM)
	}, tpm2.TPMHandle(handle), *wifProvider, *jwtIssuer, subject, *jwtLifetime, *impersonateSA)

	ts, err := externalaccount.NewTokenSource(ctx, conf)
	if err != nil {
		return nil, err
	}

	// Fail fast at startup if the TPM, the JWKS, or the IAM bindings are wrong.
	if _, err := ts.Token(); err != nil {
		return nil, fmt.Errorf("failed to obtain initial access token: %w", err)
	}
	glog.Infof("Authenticated to Google Cloud via %s as subject %q using TPM key 0x%x", *wifProvider, subject, handle)

	return oauth2.NewClient(ctx, ts), nil
}

// externalAccountConfig describes the STS exchange (and optional service
// account impersonation) for a JWT signed by the TPM key at handle.
func externalAccountConfig(
	open func() (transport.TPMCloser, error),
	handle tpm2.TPMHandle,
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
			Audience: "https://iam.googleapis.com/" + provider,
			Lifetime: lifetime,
		},
	}
	if serviceAccount != "" {
		conf.ServiceAccountImpersonationURL = fmt.Sprintf(
			"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken", serviceAccount)
	}
	return conf
}

func run(pluginManager *plugin.PluginManager, h *plugin.HealthCheckerManager, m *plugin.Metrics) error {
	signalsChan := make(chan os.Signal, 1)
	signal.Notify(signalsChan, syscall.SIGINT, syscall.SIGTERM)

	metricsErrCh := m.Serve()
	healthzErrCh := h.Serve()

	gRPCSrv, kmsErrorCh := pluginManager.Start()
	defer gRPCSrv.GracefulStop()

	for {
		select {
		case sig := <-signalsChan:
			return fmt.Errorf("captured %v, shutting down kms-plugin", sig)
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
	if !*integrationTest && (*wifProvider == "" || *jwtIssuer == "") {
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
