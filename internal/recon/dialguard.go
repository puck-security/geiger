package recon

import (
	"context"
	"errors"
	"net"
)

// ErrBlockedTarget is returned when recon would dial a cloud metadata address.
// An input-controlled endpoint/DSN — or a harvested value re-triaged internally
// — must not be usable to reach the instance metadata service (SSRF to steal
// instance credentials).
var ErrBlockedTarget = errors.New("recon: refused cloud-metadata target (possible SSRF)")

// alibabaMetadataIP (100.100.100.200) is Alibaba Cloud's metadata endpoint. It
// lives in shared address space (100.64.0.0/10), so it is NOT caught by the
// link-local check and needs an explicit block.
var alibabaMetadataIP = net.IPv4(100, 100, 100, 200)

// awsV6MetadataIP (fd00:ec2::254) is the AWS IPv6 IMDS address. It is a ULA, so
// it would only be caught by a blanket private-range block — which we avoid, to
// keep internal RFC1918/ULA triage working — hence the explicit entry.
var awsV6MetadataIP = net.ParseIP("fd00:ec2::254")

// blockedIP reports whether an IP is a cloud metadata endpoint that must never
// be dialed: link-local (169.254.0.0/16 and fe80::/10 — the AWS/GCP/Azure IMDS
// lives at 169.254.169.254) plus the two metadata addresses that fall outside
// link-local. Loopback and RFC1918 / ULA private ranges stay reachable on
// purpose: triaging a local k8s API (kubeadm/minikube at 127.0.0.1), a local
// dev database, or an internal Vault/GitLab is a legitimate, common use.
func blockedIP(ip net.IP) bool {
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	return ip.Equal(alibabaMetadataIP) || ip.Equal(awsV6MetadataIP)
}

// GuardedDial is a net.Dialer DialContext that resolves the target, refuses it
// if ANY resolved address is blocked, then dials a vetted IP literal (no TOCTOU
// re-resolve). Use it as http.Transport.DialContext for any HTTP-speaking recon
// client so an attacker-controlled host can't redirect it at metadata/loopback.
func GuardedDial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		if blockedIP(ip.IP) {
			return nil, ErrBlockedTarget
		}
	}
	var d net.Dialer
	return d.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
}
