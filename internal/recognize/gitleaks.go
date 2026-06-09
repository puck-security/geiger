package recognize

import (
	"sync"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/zricethezav/gitleaks/v8/detect"
)

var (
	detOnce sync.Once
	det     *detect.Detector
)

func detector() *detect.Detector {
	detOnce.Do(func() {
		d, err := detect.NewDetectorDefaultConfig()
		if err == nil {
			det = d
		}
	})
	return det
}

// gitleaksMatches scans the raw blob and routes each finding's rule id to a
// module via the registry. gitleaks already validates checksummed prefixes
// (GitHub CRC32, Stripe, Cloudflare), giving offline pre-validation for free.
func gitleaksMatches(b parse.Blob, reg *module.Registry) []Match {
	d := detector()
	if d == nil {
		return nil
	}
	var out []Match
	for _, f := range d.DetectString(b.Raw) {
		name, ok := reg.RuleModule(f.RuleID)
		if !ok {
			// Recognized as a secret but no Geiger module covers it yet.
			name = "__unknown__:" + f.RuleID
		}
		label := f.RuleID
		if v := varNameFor(b, f.Secret); v != "" {
			label = v
		}
		out = append(out, Match{
			Module: name,
			Fields: module.Fields{"token": f.Secret, "_rule": f.RuleID},
			Secret: f.Secret,
			Label:  label,
			Line:   f.StartLine + 1, // gitleaks StartLine is 0-based
		})
	}
	return out
}

// varNameFor finds the env/var key whose value is this secret, for a friendlier
// label ("from .env: GITHUB_TOKEN").
func varNameFor(b parse.Blob, secret string) string {
	for k, v := range b.Vars {
		if v == secret {
			return k
		}
	}
	return ""
}
