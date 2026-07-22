package modules

import "github.com/puck-security/geiger/internal/module"

// add registers a module and (optionally) maps a gitleaks rule id to it.
func add(rule string, m module.Module) {
	module.Register(m)
	if rule != "" {
		module.MapRule(rule, m.Name())
	}
}

// Endpoint-policy shorthands for the catalog. Every module whose calls are aimed
// by a URL-valued field ({endpoint}/{host}/{api}/{server}) must declare one —
// TestEveryEndpointSteeredModuleDeclaresAPolicy fails otherwise — because that
// destination comes from scanned data an attacker may have planted.
var (
	// selfHosted permits any host. Correct for services deployable at an
	// arbitrary domain, INCLUDING every vendor that ships both a SaaS and an
	// on-prem edition: pinning suffixes there would break real deployments.
	selfHosted = module.EndpointPolicy{SelfHosted: true}
)

// saasOnly pins a vendor that only ever runs on its own domains. List every
// region and government host it operates — a missing suffix silently degrades a
// legitimate credential to "needs endpoint", it does not fail safe-and-loud.
func saasOnly(suffixes ...string) module.EndpointPolicy {
	return module.EndpointPolicy{HostSuffixes: suffixes}
}

// fm is a shorthand for the force-multiplier flag in module specs.
const (
	fmFlag   = module.FlagForceMultiplier
	warnFlag = module.FlagWarn
	infoFlag = module.FlagInfo
	cantFlag = module.FlagCantCharacterize
)
