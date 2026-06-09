package modules

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSSHCandidateHosts(t *testing.T) {
	home := t.TempDir()
	ssh := filepath.Join(home, ".ssh")
	os.MkdirAll(ssh, 0o700)
	os.WriteFile(filepath.Join(ssh, "config"), []byte(
		"Host bastion\n  HostName bastion.prod.internal\n  IdentityFile ~/.ssh/id_ed25519\n\nHost *\n  ForwardAgent yes\n"), 0o600)
	os.WriteFile(filepath.Join(ssh, "known_hosts"), []byte(
		"git.example.com ssh-ed25519 AAAA\n[jump.corp.net]:2222 ssh-rsa BBBB\n|1|hashedhostxxxx ssh-ed25519 CCCC\n"), 0o600)
	os.WriteFile(filepath.Join(home, ".bash_history"), []byte(
		"ls -la\nssh deploy@app01.prod.internal\nssh -i ~/.ssh/k localhost\n"), 0o600)

	got := sshCandidateHosts(home)
	want := map[string]bool{
		"bastion.prod.internal": true, // config HostName
		"git.example.com":       true, // known_hosts
		"jump.corp.net":         true, // known_hosts [host]:port
		"app01.prod.internal":   true, // history
	}
	gotSet := map[string]bool{}
	for _, h := range got {
		gotSet[h] = true
	}
	for w := range want {
		if !gotSet[w] {
			t.Errorf("expected candidate host %q, got %v", w, got)
		}
	}
	// must NOT include wildcards, hashed entries, or localhost
	for _, bad := range []string{"*", "localhost"} {
		if gotSet[bad] {
			t.Errorf("should not include %q", bad)
		}
	}
}
