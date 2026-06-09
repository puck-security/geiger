package recon

import (
	"context"
	"net"
	"testing"
)

func TestBlockedIP(t *testing.T) {
	blocked := []string{
		"169.254.169.254", // AWS/GCP/Azure IMDS (link-local)
		"169.254.0.1",     // link-local
		"100.100.100.200", // Alibaba Cloud metadata
		"fd00:ec2::254",   // AWS IPv6 IMDS
		"fe80::1",         // link-local v6
	}
	for _, s := range blocked {
		if !blockedIP(net.ParseIP(s)) {
			t.Errorf("%s should be blocked", s)
		}
	}
	allowed := []string{
		"127.0.0.1",    // loopback — local k8s/DB triage is legitimate
		"::1",          // loopback v6
		"10.0.0.5",     // RFC1918 — internal triage is legitimate
		"192.168.1.10", // RFC1918
		"172.16.0.1",   // RFC1918
		"fd00:1234::1", // ULA (not the IMDS address)
		"8.8.8.8",      // public
		"100.64.0.1",   // shared address space, but not the metadata host
	}
	for _, s := range allowed {
		if blockedIP(net.ParseIP(s)) {
			t.Errorf("%s should be allowed (internal/local/public triage)", s)
		}
	}
}

func TestGuardedDialRefusesMetadata(t *testing.T) {
	for _, addr := range []string{"169.254.169.254:80", "100.100.100.200:80", "[fd00:ec2::254]:80"} {
		if _, err := GuardedDial(context.Background(), "tcp", addr); err != ErrBlockedTarget {
			t.Errorf("GuardedDial(%s) = %v, want ErrBlockedTarget", addr, err)
		}
	}
}
