package modules

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/recon"
	"golang.org/x/crypto/ssh"
)

func TestSSHEncryptedKeyIsLockedNotDead(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "geiger@test", []byte("hunter2"))
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := string(pem.EncodeToMemory(block))

	fs, err := sshKey{}.Recon(context.Background(), recon.New(nil, false), module.Token{}, module.Fields{"key": keyPEM})
	if err != nil {
		t.Fatal(err)
	}
	got := indexByKey(fs)
	// encrypted = locked, not dead → CantCharacterize, never invalid.
	if got["encrypted"].Flag != module.FlagCantCharacterize {
		t.Errorf("encrypted key should be CantCharacterize, got %+v", got["encrypted"])
	}
	note := sshKey{}.Summarize("t", fs)
	if note.Invalid {
		t.Errorf("encrypted key must not be marked dead/invalid")
	}
	// OpenSSH format embeds the public key, so the fingerprint is still recoverable.
	if got["type"].Value != "ssh-ed25519" {
		t.Errorf("fingerprint not recovered from embedded pubkey: %+v", got["type"])
	}
	if got["fingerprint"].Value == "" {
		t.Errorf("expected a fingerprint for the OpenSSH-format encrypted key")
	}
}

func TestSSHPlainKeyFingerprints(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, err := ssh.MarshalPrivateKey(priv, "geiger@test")
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := string(pem.EncodeToMemory(block))
	fs, _ := sshKey{}.Recon(context.Background(), recon.New(nil, false), module.Token{}, module.Fields{"key": keyPEM})
	got := indexByKey(fs)
	if got["type"].Value != "ssh-ed25519" || got["fingerprint"].Value == "" {
		t.Errorf("plain key not fingerprinted: %+v", fs)
	}
	if got["encrypted"].Key != "" {
		t.Errorf("plain key should not be flagged encrypted")
	}
}
