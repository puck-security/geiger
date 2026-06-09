package recipe

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/puck-security/geiger/internal/module"
)

// The heuristic scanner makes extraction resilient to API drift: even if a
// module's declared JSON paths break, a generic walk of the response still
// surfaces the high-signal facts — privilege (admin/owner/root), PII (emails),
// and, when declared extraction yields nothing, a fallback identity and the
// largest collection's size.

var emailRe = regexp.MustCompile(`[\w.+-]+@[\w-]+\.[A-Za-z]{2,}`)
var adminValRe = regexp.MustCompile(`(?i)\b(admin|administrator|owner|superuser|super_admin|root|cluster-admin)\b`)

type scanResult struct {
	privileged bool
	privDetail string
	pii        bool
	idCand     map[string]string // identity-key -> value (best chosen by priority)
	arrKey     string
	arrLen     int
}

// identityPriority orders identity keys so the fallback identity is
// deterministic regardless of map iteration order (login/username before email,
// which is separately flagged as PII).
var identityPriority = []string{"login", "username", "user", "name", "handle", "display_name", "displayname", "full_name", "slug", "email"}

func (r scanResult) identity() (key, val string) {
	for _, k := range identityPriority {
		if v, ok := r.idCand[k]; ok && v != "" {
			return k, v
		}
	}
	return "", ""
}

func scanJSON(v any) scanResult {
	var r scanResult
	nodes := 0
	var walk func(key string, v any, depth int)
	walk = func(key string, v any, depth int) {
		if depth > 5 || nodes > 5000 {
			return
		}
		nodes++
		switch t := v.(type) {
		case map[string]any:
			for k, vv := range t {
				lk := strings.ToLower(k)
				switch s := vv.(type) {
				case bool:
					if s && isAdminKey(lk) {
						r.privileged = true
						if r.privDetail == "" {
							r.privDetail = k + "=true"
						}
					}
				case string:
					if isRoleKey(lk) && adminValRe.MatchString(s) {
						r.privileged = true
						if r.privDetail == "" {
							r.privDetail = k + "=" + s
						}
					}
					if isIdentityKey(lk) && s != "" && len(s) < 120 {
						if r.idCand == nil {
							r.idCand = map[string]string{}
						}
						if _, ok := r.idCand[lk]; !ok {
							r.idCand[lk] = s
						}
					}
					if emailRe.MatchString(s) {
						r.pii = true
					}
				}
				walk(k, vv, depth+1)
			}
		case []any:
			if key != "" && len(t) > r.arrLen {
				r.arrLen, r.arrKey = len(t), key
			}
			for i, e := range t {
				if i > 50 {
					break
				}
				walk(key, e, depth+1)
			}
		case string:
			if emailRe.MatchString(t) {
				r.pii = true
			}
		}
	}
	walk("", v, 0)
	return r
}

func isAdminKey(k string) bool {
	return strings.Contains(k, "admin") || strings.Contains(k, "superuser") ||
		k == "owner" || k == "is_owner" || strings.Contains(k, "is_admin")
}

func isRoleKey(k string) bool {
	return k == "role" || k == "roles" || strings.Contains(k, "role") ||
		strings.Contains(k, "permission") || k == "access_level" || k == "user_type" || k == "scope"
}

func isIdentityKey(k string) bool {
	switch k {
	case "email", "login", "username", "user", "name", "handle", "display_name", "displayname", "slug", "full_name":
		return true
	}
	return false
}

// heuristicFindings returns supplemental, drift-resilient findings. When
// declaredEmpty is true (the module's declared paths matched nothing) it also
// falls back to a generic identity and collection count.
func heuristicFindings(decoded any, declaredEmpty bool) []module.Finding {
	r := scanJSON(decoded)
	var out []module.Finding
	if r.privileged {
		out = append(out, module.Finding{Key: "privileged", Value: r.privDetail + "  — admin/owner-level access", Flag: module.FlagForceMultiplier})
	}
	if r.pii {
		out = append(out, module.Finding{Key: "PII", Value: "response exposes email/PII fields", Flag: module.FlagWarn})
	}
	if declaredEmpty {
		if k, v := r.identity(); v != "" {
			out = append(out, module.Finding{Key: "identity", Value: k + "=" + v, Flag: module.FlagInfo})
		}
		if r.arrLen > 0 {
			out = append(out, module.Finding{Key: r.arrKey, Value: strconv.Itoa(r.arrLen) + " (detected)", Flag: module.FlagInfo})
		}
	}
	return out
}
