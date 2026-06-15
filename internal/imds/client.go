package imds

import (
	"context"
	"io"
	"net"
	"net/http"
	"time"
)

// metadataClient builds the ONLY un-guarded HTTP client in geiger. It exists
// solely to read credentials FROM the instance-metadata service for the explicit,
// operator-initiated --metadata mode. It MUST NEVER be handed to a recon.Client, a
// module, or anything in internal/recon or internal/pipeline: all credential
// *recon* runs on the guarded client (internal/pipeline.httpClient →
// recon.GuardedDial), which refuses metadata targets. This bypass is confined to
// this package so a harvested value can never pivot back to the metadata service.
//
// The metadata service is local link-local infrastructure, so the request is NOT
// routed through --proxy (which is for recon egress).
func metadataClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{Timeout: timeout}).DialContext,
		},
	}
}

// get issues a GET (with optional header setup) through the un-guarded metadata
// client and returns the body when the status is 2xx. Bodies are bounded.
func get(ctx context.Context, hc *http.Client, url string, setup func(*http.Request)) ([]byte, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false
	}
	if setup != nil {
		setup(req)
	}
	return do(hc, req)
}

func do(hc *http.Client, req *http.Request) ([]byte, bool) {
	resp, err := hc.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, false
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, false
	}
	return b, true
}
