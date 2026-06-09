package module

import "fmt"

// Registry holds the available modules and the routes into them.
type Registry struct {
	byName map[string]Module
	byRule map[string]string // gitleaks rule id -> module name
	order  []string
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{byName: map[string]Module{}, byRule: map[string]string{}}
}

// Default is the process-wide registry that modules self-register into.
var Default = NewRegistry()

// Register adds a module. It panics on a duplicate name (a programming error).
func (r *Registry) Register(m Module) {
	name := m.Name()
	if _, dup := r.byName[name]; dup {
		panic(fmt.Sprintf("module: duplicate registration %q", name))
	}
	r.byName[name] = m
	r.order = append(r.order, name)
}

// MapRule routes a gitleaks rule id to a module name.
func (r *Registry) MapRule(ruleID, moduleName string) {
	r.byRule[ruleID] = moduleName
}

// ByName returns a module by name.
func (r *Registry) ByName(name string) (Module, bool) {
	m, ok := r.byName[name]
	return m, ok
}

// ByRule returns the module a gitleaks rule routes to.
func (r *Registry) ByRule(ruleID string) (Module, bool) {
	name, ok := r.byRule[ruleID]
	if !ok {
		return nil, false
	}
	return r.ByName(name)
}

// RuleModule returns the module name a rule maps to.
func (r *Registry) RuleModule(ruleID string) (string, bool) {
	name, ok := r.byRule[ruleID]
	return name, ok
}

// All returns modules in registration order.
func (r *Registry) All() []Module {
	out := make([]Module, 0, len(r.order))
	for _, n := range r.order {
		out = append(out, r.byName[n])
	}
	return out
}

// Rules returns a copy of the rule→module mapping (for tests/introspection).
func (r *Registry) Rules() map[string]string {
	out := make(map[string]string, len(r.byRule))
	for k, v := range r.byRule {
		out[k] = v
	}
	return out
}

// Register adds a module to the default registry.
func Register(m Module) { Default.Register(m) }

// MapRule routes a rule id in the default registry.
func MapRule(ruleID, moduleName string) { Default.MapRule(ruleID, moduleName) }
