// Package imds harvests credentials from cloud instance-metadata services (AWS
// IMDS, GCP/Azure metadata, Kubernetes in-cluster SA, Alibaba, DigitalOcean, OCI)
// and normalizes each into a synthetic dotenv blob that geiger's normal
// recognizers pick up. The metadata fetch is the only place geiger bypasses the
// SSRF dial guard (see client.go); every harvested credential is then triaged
// through the unchanged, guarded recon pipeline.
package imds

import (
	"context"
	"net/http"
	"sync"
	"time"
)

// Options configures a harvest.
type Options struct {
	Timeout time.Duration // per-provider probe timeout (default 2s)
}

// Cred is one harvested credential, expressed as a synthetic dotenv blob plus a
// provenance label, so the standard pipeline (parse.Parse → recognize.Recognize →
// recon) triages it through the matching module.
type Cred struct {
	Cloud  string // "aws" | "gcp" | "azure" | "kubernetes" | "alibaba" | "digitalocean" | "oci"
	Label  string // provenance, e.g. "metadata: aws instance role ec2-app"
	Blob   string // synthetic dotenv text the recognizers consume
	Secret string // raw secret value (for redaction)
}

// fetcher reads whatever credentials a single provider's metadata service exposes.
type fetcher struct {
	cloud string
	fn    func(ctx context.Context, hc *http.Client) []Cred
}

func fetchers() []fetcher {
	return []fetcher{
		{"aws", fetchAWS},
		{"gcp", fetchGCP},
		{"azure", fetchAzure},
		{"kubernetes", fetchK8s},
		{"alibaba", fetchAlibaba},
		{"digitalocean", fetchDigitalOcean},
		{"oci", fetchOCI},
	}
}

// Harvest probes every supported provider concurrently (absent endpoints time out
// quietly) and returns the credentials it could read plus the clouds that
// responded. It never returns secrets in the error or cloud list.
func Harvest(ctx context.Context, o Options) (creds []Cred, clouds []string, err error) {
	if o.Timeout == 0 {
		o.Timeout = 2 * time.Second
	}
	hc := metadataClient(o.Timeout)

	fs := fetchers()
	out := make([][]Cred, len(fs))
	var wg sync.WaitGroup
	for i := range fs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			fctx, cancel := context.WithTimeout(ctx, o.Timeout)
			defer cancel()
			out[i] = fs[i].fn(fctx, hc)
		}(i)
	}
	wg.Wait()

	for i, f := range fs {
		if len(out[i]) > 0 {
			creds = append(creds, out[i]...)
			clouds = append(clouds, f.cloud)
		}
	}
	return creds, clouds, nil
}
