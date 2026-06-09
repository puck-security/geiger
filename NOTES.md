# geiger — design notes & deferred ideas

Scratchpad for capabilities considered but intentionally not built (yet), and
why. Keep this honest so we don't re-litigate the same trade-offs.

## Deferred

### Browser-stored logins / cookies (DEFERRED — note only)

Supply-chain malware and infostealers routinely read browser credential stores:

- Chromium (`Login Data`, `Cookies`, `Web Data`) — AES-GCM values wrapped by an
  OS keychain key (`Local State` `os_crypt.encrypted_key`; on Linux often
  `peanuts`/`v11` via Secret Service/kwallet; on macOS the `Chrome Safe Storage`
  keychain item; on Windows DPAPI). Chrome 127+ adds app-bound encryption.
- Firefox `logins.json` + `key4.db` (NSS, master-password-derived).
- Session cookies are the high-value target: a live `__Secure-...`/SSO cookie
  bypasses MFA entirely (the same pivot as a stolen OAuth refresh token).

**Why deferred, not declined:** it fits geiger's thesis (a stolen browser
cookie *is* a credential with real blast radius), but reading these stores means
OS-keychain decryption that is (a) platform-specific, (b) prompts the user's
keychain/Secret Service, and (c) edges from "triage a credential you were handed"
toward "extract credentials from a live endpoint." If we build it, gate it hard
(explicit `--browser` opt-in, local-only, never network the cookie) and triage a
cookie the same way we triage a token: identity call + reach sizing against the
issuing service.

## Possible future work

- LLM generalist for unrecognized credential types (the one explicitly-excluded
  piece of the original spec).
- More secrets-store harvesters as providers are added (HashiCorp Vault KV walk,
  Doppler/1Password downstream reads — partly covered).
