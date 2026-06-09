package modules

import "github.com/puck-security/geiger/internal/module"

// add registers a module and (optionally) maps a gitleaks rule id to it.
func add(rule string, m module.Module) {
	module.Register(m)
	if rule != "" {
		module.MapRule(rule, m.Name())
	}
}

// fm is a shorthand for the force-multiplier flag in module specs.
const (
	fmFlag   = module.FlagForceMultiplier
	warnFlag = module.FlagWarn
	infoFlag = module.FlagInfo
	cantFlag = module.FlagCantCharacterize
)
