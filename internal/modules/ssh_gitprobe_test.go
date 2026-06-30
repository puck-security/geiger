package modules

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/recon"
	"golang.org/x/crypto/ssh"
)

func TestGitIdentity(t *testing.T) {
	cases := []struct {
		host, banner, id string
		deploy           bool
	}{
		{"github.com", "Hi octocat! You've successfully authenticated, but GitHub does not provide shell access.", "octocat", false},
		{"github.com", "Hi acme/widgets! You've successfully authenticated, but GitHub does not provide shell access.", "acme/widgets", true},
		{"gitlab.com", "Welcome to GitLab, @octocat!", "octocat", false},
		{"bitbucket.org", "authenticated as octocat. You can use git to connect to Bitbucket.", "octocat", false},
		{"bitbucket.org", "You can use git or hg to connect to Bitbucket. Shell access is disabled.", "", false},
	}
	for _, c := range cases {
		id, deploy := gitIdentity(c.host, c.banner)
		if id != c.id || deploy != c.deploy {
			t.Errorf("gitIdentity(%s) = (%q,%v), want (%q,%v)", c.host, id, deploy, c.id, c.deploy)
		}
	}
}

// startGitSSHServer runs a one-shot in-process SSH server that accepts only
// clientPub and emits banner on the session, mimicking GitHub/GitLab/Bitbucket.
func startGitSSHServer(t *testing.T, clientPub ssh.PublicKey, accept bool, banner string) string {
	t.Helper()
	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			if accept && bytes.Equal(k.Marshal(), clientPub.Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, errAuthDenied
		},
	}
	cfg.AddHostKey(hostSigner)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		nc, err := ln.Accept()
		if err != nil {
			return
		}
		sc, chans, reqs, err := ssh.NewServerConn(nc, cfg)
		if err != nil {
			nc.Close()
			return
		}
		go ssh.DiscardRequests(reqs)
		for newCh := range chans {
			if newCh.ChannelType() != "session" {
				newCh.Reject(ssh.UnknownChannelType, "")
				continue
			}
			ch, creqs, err := newCh.Accept()
			if err != nil {
				continue
			}
			go func() {
				for req := range creqs {
					if req.Type == "exec" || req.Type == "shell" {
						if req.WantReply {
							req.Reply(true, nil)
						}
						ch.Write([]byte(banner))
						ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{1}))
						ch.Close()
						return
					}
					if req.WantReply {
						req.Reply(false, nil)
					}
				}
			}()
		}
		sc.Close()
	}()
	return ln.Addr().String()
}

var errAuthDenied = &authDeniedErr{}

type authDeniedErr struct{}

func (*authDeniedErr) Error() string { return "denied" }

func newClientSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestProbeGitHostAccepted(t *testing.T) {
	signer := newClientSigner(t)
	addr := startGitSSHServer(t, signer.PublicKey(), true,
		"Hi octocat! You've successfully authenticated, but GitHub does not provide shell access.\n")
	accepted, banner, transportErr := probeGitHost(context.Background(), signer, addr)
	if transportErr || !accepted {
		t.Fatalf("expected accepted, got accepted=%v transportErr=%v", accepted, transportErr)
	}
	if id, _ := gitIdentity("github.com", banner); id != "octocat" {
		t.Errorf("identity from banner = %q, want octocat", id)
	}
}

func TestProbeGitHostRejected(t *testing.T) {
	signer := newClientSigner(t)
	// server rejects the key → reached the host, but key not accepted.
	addr := startGitSSHServer(t, signer.PublicKey(), false, "")
	accepted, _, transportErr := probeGitHost(context.Background(), signer, addr)
	if accepted {
		t.Errorf("rejected key should not be accepted")
	}
	if transportErr {
		t.Errorf("a key rejection is not a transport error (the host was reached)")
	}
}

func TestSSHDryRunDefersHostCheck(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := string(pem.EncodeToMemory(block))
	fs, err := sshKey{}.Recon(context.Background(), recon.New(nil, false), module.Token{}, module.Fields{"key": keyPEM})
	if err != nil {
		t.Fatal(err)
	}
	var got string
	for _, f := range fs {
		if f.Key == "host acceptance" {
			got = f.Value
		}
		for _, h := range gitSSHHosts {
			if f.Key == h {
				t.Errorf("dry-run must not probe %s", h)
			}
		}
	}
	if got == "" || !bytes.Contains([]byte(got), []byte("--live")) {
		t.Errorf("dry-run should defer to --live, got host acceptance = %q", got)
	}
}
