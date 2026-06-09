// Package color provides terminal coloring that is a no-op unless enabled, so
// output stays clean when piped or redirected (codes would otherwise pollute
// files and tools like jq).
package color

// Enabled gates all coloring. The CLI sets it from TTY detection / --color /
// NO_COLOR. When false, every helper returns its input unchanged.
var Enabled bool

const (
	reset     = "\x1b[0m"
	bold      = "\x1b[1m"
	dim       = "\x1b[2m"
	red       = "\x1b[31m"
	brightRed = "\x1b[91m"
	yellow    = "\x1b[33m"
	cyan      = "\x1b[36m"
)

func wrap(code, s string) string {
	if !Enabled || s == "" {
		return s
	}
	return code + s + reset
}

// Dim renders de-emphasized text (info/dead, comments).
func Dim(s string) string { return wrap(dim, s) }

// Warn renders the ⚠ (notable) level.
func Warn(s string) string { return wrap(yellow, s) }

// Force renders the ⚠⚠ (force-multiplier) level.
func Force(s string) string { return wrap(bold+brightRed, s) }

// Cant renders the ? (can't-characterize) level.
func Cant(s string) string { return wrap(cyan, s) }

// Tier colors a tier label by name.
func Tier(name string) string {
	switch name {
	case "CRITICAL":
		return wrap(bold+brightRed, name)
	case "HIGH":
		return wrap(red, name)
	case "MEDIUM":
		return wrap(yellow, name)
	case "DEAD":
		return wrap(dim, name)
	case "INFO":
		return wrap(dim, name)
	default: // LOW
		return name
	}
}
