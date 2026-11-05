//go:build !windows

package modules

// validateWindowsLogon is a no-op off Windows: local LogonUser validation is a
// Windows-only API. supported=false tells the caller to say so rather than
// report a credential as rejected.
func validateWindowsLogon(_, _ string) (ok bool, supported bool, detail string) {
	return false, false, ""
}
