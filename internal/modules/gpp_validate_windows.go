//go:build windows

package modules

import (
	"strings"
	"syscall"
	"unsafe"
)

// validateWindowsLogon tests a username/password against Windows authentication
// via the LogonUser API (advapi32). It uses a network logon, which validates
// the credential without loading a user profile. No third-party dependency: the
// stdlib syscall package exposes LazyDLL on Windows. ok reports acceptance,
// supported is always true here, and detail carries the OS error on rejection.
func validateWindowsLogon(name, password string) (ok bool, supported bool, detail string) {
	const (
		logon32LogonNetwork    = 3
		logon32ProviderDefault = 0
	)
	user, domain := splitLogonName(name)
	up, err := syscall.UTF16PtrFromString(user)
	if err != nil {
		return false, true, "bad username"
	}
	dp, _ := syscall.UTF16PtrFromString(domain)
	pp, _ := syscall.UTF16PtrFromString(password)

	logonUser := syscall.NewLazyDLL("advapi32.dll").NewProc("LogonUserW")
	var token syscall.Handle
	r1, _, callErr := logonUser.Call(
		uintptr(unsafe.Pointer(up)),
		uintptr(unsafe.Pointer(dp)),
		uintptr(unsafe.Pointer(pp)),
		logon32LogonNetwork,
		logon32ProviderDefault,
		uintptr(unsafe.Pointer(&token)),
	)
	if r1 != 0 {
		syscall.CloseHandle(token)
		return true, true, ""
	}
	return false, true, callErr.Error()
}

// splitLogonName turns a GPP account name into the (user, domain) pair LogonUser
// expects: "DOMAIN\user" splits; a UPN ("user@domain") passes with an empty
// domain; a bare name validates against the local machine (".").
func splitLogonName(name string) (user, domain string) {
	name = strings.TrimSuffix(name, " (built-in)")
	if i := strings.IndexByte(name, '\\'); i >= 0 {
		return name[i+1:], name[:i]
	}
	if strings.ContainsRune(name, '@') {
		return name, ""
	}
	return name, "."
}
