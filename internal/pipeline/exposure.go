package pipeline

import (
	"path/filepath"
	"strings"

	"github.com/puck-security/geiger/internal/module"
)

// classifyExposure reads a source path the way an IR responder would and returns
// a short grouping class, a one-line risk note, and a significance flag. The
// *where* a credential was found is often as important as what it is: a token in
// a crash dump (memory persisted to disk, frequently auto-uploaded to the
// vendor) is a far worse exposure than the same token in a .env. An empty class
// means "ordinary file" — the path is already in the title, so no finding is
// added (avoid noise).
//
// classes are stable labels used both for the per-finding note and to group the
// "also exposed in" rollup. Match order matters (first hit wins).
func classifyExposure(path string) (class, note string, flag module.FlagLevel) {
	p := strings.ToLower(filepath.ToSlash(path))
	base := strings.ToLower(filepath.Base(path))

	// class is a SINGULAR noun (the rollup pluralizes with +s).
	switch {
	case strings.HasPrefix(path, "harvested via "):
		// provenance, not a filesystem location — name the store it came from.
		store := strings.TrimPrefix(path, "harvested via ")
		if i := strings.IndexByte(store, ':'); i > 0 {
			store = store[:i]
		}
		return "harvested secret", "harvested from a credential store (" + store + ") — not a standalone file", module.FlagInfo
	case strings.HasPrefix(path, "gitleaks:"), strings.HasPrefix(path, "trufflehog:"):
		return "scanner finding", "from a secret-scanner report — confirm the on-disk source", module.FlagInfo

	case strings.Contains(p, "/crashpad/"), strings.Contains(p, "/cores/"),
		hasSuffixAny(base, ".dmp", ".mdmp", ".hprof", ".core"), strings.HasPrefix(base, "core."):
		return "crash dump",
			"crash dump — credential was in process memory, persisted to disk; crash reports are often auto-uploaded to the vendor, so it may have left this host",
			module.FlagWarn

	case strings.Contains(p, "/code/user/history/"), strings.Contains(p, "/.history/"),
		strings.Contains(p, "/localhistory/"):
		return "editor local-history snapshot",
			"editor local-history snapshot — an auto-saved copy of a file being edited (the secret was in source)",
			module.FlagInfo

	case strings.HasSuffix(p, ".vscdb"), strings.Contains(p, "/globalstorage/"):
		return "IDE secret store", "IDE secret store (plaintext on disk)", module.FlagInfo

	case base == ".bash_history", base == ".zsh_history", base == ".history",
		base == "fish_history", base == ".python_history", base == ".psql_history":
		return "shell history file", "shell history — typed on the command line (and visible to anything reading the history file)", module.FlagWarn

	case strings.Contains(p, "/.git/"):
		return "git object", "git internals — committed to the repository and recoverable from history", module.FlagInfo

	case strings.HasSuffix(p, ".log"), strings.Contains(p, "/logs/"):
		return "log file", "log file — secret written to a log (often shipped to centralized logging)", module.FlagInfo
	}
	return "", "", module.FlagInfo
}

func hasSuffixAny(s string, sfx ...string) bool {
	for _, x := range sfx {
		if strings.HasSuffix(s, x) {
			return true
		}
	}
	return false
}
