package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"

	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/miekg/dns"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(GroupName,
		&RcodeZeroDNSProviderSolver{},
	)
}

// RcodeZeroDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for RcodeZero DNS provider.
type RcodeZeroDNSProviderSolver struct {
	// If a Kubernetes 'clientset' is needed, you must:
	// 1. uncomment the additional `client` field in this structure below
	// 2. uncomment the "k8s.io/client-go/kubernetes" import at the top of the file
	// 3. uncomment the relevant code in the Initialize method below
	// 4. ensure your webhook's service account has the required RBAC role
	//    assigned to it for interacting with the Kubernetes APIs you need.
	client *kubernetes.Clientset
}

// customDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.
type RcodeZeroDNSProviderConfig struct {
	// Change the two fields below according to the format of the configuration
	// to be decoded.
	// These fields will be set by users in the
	// `issuer.spec.acme.dns01.providers.webhook.config` field.

	APIKeySecretRef *cmmeta.SecretKeySelector `json:"apiKeySecretRef"`
}

const defaultBaseURL = "https://my.rcodezero.at/api"

const authorizationHeader = "Authorization"

// Client for the RcodeZero API.
type Client struct {
	apiToken string

	baseURL    *url.URL
	HTTPClient *http.Client
}

type UpdateRRSet struct {
	Name       string   `json:"name"`
	Type       string   `json:"type"`
	ChangeType string   `json:"changetype"`
	Records    []Record `json:"records"`
	TTL        int      `json:"ttl"`
}

type Record struct {
	Content  string `json:"content"`
	Disabled bool   `json:"disabled"`
}

type APIResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *RcodeZeroDNSProviderSolver) Name() string {
	return "rcodezero"
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *RcodeZeroDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	ctx := context.Background()

	klog.InfoS("Presenting challenge", "dnsName", ch.DNSName, "resolvedZone", ch.ResolvedZone, "resolvedFQDN", ch.ResolvedFQDN)

	provider, _, err := c.init(ch.Config, ch.ResourceNamespace)
	if err != nil {
		klog.Errorf("failed initializing rcodezero provider: %v", err)
		return nil
	}

	rrSet := []UpdateRRSet{{
		Name:       ch.ResolvedFQDN,
		ChangeType: "update",
		Type:       "TXT",
		TTL:        60,
		Records:    []Record{{Content: `"` + ch.Key + `"`}},
	}}

	_, err = provider.UpdateRecords(ctx, ch.ResolvedZone, rrSet)

	if err != nil {
		klog.Errorf("Error Adding Record: %v\n", err)
		return (err)
	}

	klog.Infof("Presented txt record %v", ch.ResolvedFQDN)

	return nil

}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *RcodeZeroDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {

	ctx := context.Background()

	klog.InfoS("Removing challenge", "dnsName", ch.DNSName, "resolvedZone", ch.ResolvedZone, "resolvedFQDN", ch.ResolvedFQDN)

	provider, _, err := c.init(ch.Config, ch.ResourceNamespace)
	if err != nil {
		klog.Errorf("failed initializing rcodezero provider: %v", err)
		return nil
	}

	rrSet := []UpdateRRSet{{
		Name:       ch.ResolvedFQDN,
		ChangeType: "delete",
		Type:       "TXT",
		Records:    []Record{{Content: `"` + ch.Key + `"`}},
	}}

	_, err = provider.UpdateRecords(ctx, ch.ResolvedZone, rrSet)

	if err != nil {
		klog.Errorf("Error Deleting Record: %v\n", err)
		return (err)
	}

	klog.Infof("Deleted txt record %v", ch.ResolvedFQDN)

	return nil

}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (c *RcodeZeroDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	///// UNCOMMENT THE BELOW CODE TO MAKE A KUBERNETES CLIENTSET AVAILABLE TO
	///// YOUR CUSTOM DNS PROVIDER

	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	c.client = cl

	///// END OF CODE TO MAKE KUBERNETES CLIENTSET AVAILABLE
	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (*RcodeZeroDNSProviderConfig, error) {
	cfg := RcodeZeroDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return &cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return &cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return &cfg, nil
}

func (c *RcodeZeroDNSProviderSolver) init(config *extapi.JSON, namespace string) (*Client, *RcodeZeroDNSProviderConfig, error) {
	// Load and validate the configuration
	cfg, err := loadConfig(config)
	if err != nil {
		return nil, nil, fmt.Errorf("failed parsing provider config: %v", err)
	}

	// Load the API key secret
	sec, err := c.client.CoreV1().Secrets(namespace).Get(context.TODO(), cfg.APIKeySecretRef.LocalObjectReference.Name, metav1.GetOptions{})
	if err != nil {
		return nil, cfg, fmt.Errorf("failed loading api key secret %s/%s: %v", namespace, cfg.APIKeySecretRef.LocalObjectReference.Name, err)
	}

	secBytes, ok := sec.Data[cfg.APIKeySecretRef.Key]
	if !ok {
		return nil, cfg, fmt.Errorf("key %q not found in secret \"%s/%s\"", cfg.APIKeySecretRef.Key, cfg.APIKeySecretRef.LocalObjectReference.Name, namespace)
	}

	apiToken := string(secBytes)

	// Create the client
	return NewClient(apiToken), cfg, nil
}

// NewClient creates a new Client.
func NewClient(apiToken string) *Client {
	baseURL, _ := url.Parse(defaultBaseURL)

	return &Client{
		apiToken:   apiToken,
		baseURL:    baseURL,
		HTTPClient: &http.Client{Timeout: 60 * time.Second},
	}
}

func (c *Client) UpdateRecords(ctx context.Context, authZone string, sets []UpdateRRSet) (*APIResponse, error) {
	endpoint := c.baseURL.JoinPath("v1", "acme", "zones", strings.TrimSuffix(dns.Fqdn(authZone), "."), "rrsets")

	//	fmt.Printf("Got Endpoint: %s", endpoint)
	req, err := newJSONRequest(ctx, http.MethodPatch, endpoint, sets)
	if err != nil {
		return nil, err
	}

	return c.do(req)
}

func (c *Client) do(req *http.Request) (*APIResponse, error) {
	req.Header.Set(authorizationHeader, "Bearer "+c.apiToken)
	//	fmt.Printf("Token: %s", c.apiToken)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error doing HTTP request: %s", err)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode/100 != 2 {
		return nil, parseError(req, resp)
	}

	result := &APIResponse{}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error doing HTTP request: %s", err)
	}

	err = json.Unmarshal(raw, result)
	if err != nil {
		return nil, fmt.Errorf("error doing HTTP request: %s", err)
	}

	return result, nil
}

func newJSONRequest(ctx context.Context, method string, endpoint *url.URL, payload any) (*http.Request, error) {
	buf := new(bytes.Buffer)

	if payload != nil {
		err := json.NewEncoder(buf).Encode(payload)
		if err != nil {
			return nil, fmt.Errorf("failed to create request JSON body: %w", err)
		}
	}

	//	fmt.Printf("Buffer: %s", buf)

	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), buf)
	if err != nil {
		return nil, fmt.Errorf("unable to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")

	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	return req, nil
}

func parseError(_ *http.Request, resp *http.Response) error {
	raw, _ := io.ReadAll(resp.Body)

	errAPI := &APIResponse{}
	err := json.Unmarshal(raw, errAPI)
	if err != nil {
		return fmt.Errorf(`error parsing response: %w %s`, err, string(raw[:]))
	}

	return fmt.Errorf("[status code: %d] %v", resp.StatusCode, errAPI)
}
