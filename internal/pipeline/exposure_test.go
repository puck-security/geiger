package pipeline

import (
	"testing"

	"github.com/puck-security/geiger/internal/module"
)

func TestClassifyExposure(t *testing.T) {
	cases := []struct {
		path  string
		class string
		flag  module.FlagLevel
	}{
		{"/Users/x/Library/Application Support/Code/Crashpad/completed/abc.dmp", "crash dump", module.FlagWarn},
		{"/home/x/.cache/cores/core.1234", "crash dump", module.FlagWarn},
		{"/Users/x/Library/Application Support/Code/User/History/4d6f1fb5/5Kdt.py", "editor local-history snapshot", module.FlagInfo},
		{"/proj/.history/config.py", "editor local-history snapshot", module.FlagInfo},
		{"/Users/x/Library/Application Support/Code/User/globalStorage/state.vscdb", "IDE secret store", module.FlagInfo},
		{"/home/x/.zsh_history", "shell history file", module.FlagWarn},
		{"/srv/app/logs/app.log", "log file", module.FlagInfo},
		{"/proj/.git/objects/ab/cdef", "git object", module.FlagInfo},
		{"harvested via ai_ide_store: vscdb:cursorAuth/accessToken", "harvested secret", module.FlagInfo},
		{"trufflehog:GitHub", "scanner finding", module.FlagInfo},
		{"/proj/.env", "", module.FlagInfo},               // ordinary file → no class
		{"/proj/config/settings.py", "", module.FlagInfo}, // ordinary file → no class
	}
	for _, c := range cases {
		class, note, flag := classifyExposure(c.path)
		if class != c.class {
			t.Errorf("classifyExposure(%q) class = %q, want %q", c.path, class, c.class)
		}
		if class != "" {
			if flag != c.flag {
				t.Errorf("classifyExposure(%q) flag = %v, want %v", c.path, flag, c.flag)
			}
			if note == "" {
				t.Errorf("classifyExposure(%q) returned a class but empty note", c.path)
			}
		}
	}
}
