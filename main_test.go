package main

import (
	"os"
	"testing"
	"time"

	dns "github.com/cert-manager/cert-manager/test/acme"
)

var (
	zone      = getEnv("TEST_ZONE_NAME", "test.")
	dnsServer = getEnv("TEST_DNS_SERVER", "8.8.8.8:53")
)

func TestRunsSuite(t *testing.T) {
	// The manifest path should contain a file named config.json that is a
	// snippet of valid configuration that should be included on the
	// ChallengeRequest passed as part of the test cases.
	//

	fixture := dns.NewFixture(&RcodeZeroDNSProviderSolver{},
		dns.SetDNSServer(dnsServer),
		dns.SetResolvedZone(zone),
		dns.SetAllowAmbientCredentials(false),
		dns.SetManifestPath("testdata/rcodezero"),
		dns.SetStrict(true),
		dns.SetPropagationLimit(240*time.Second),
	)

	fixture.RunConformance(t)
	fixture.RunBasic(t)
	fixture.RunExtended(t)
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
