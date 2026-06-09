package modules

import (
	"context"
	"net/http"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
	"github.com/puck-security/geiger/internal/score"
)

func TestOnePasswordSecretKeyRoutedAndFlagged(t *testing.T) {
	// gitleaks detects the A3- shape; we map that rule to our offline module.
	raw := "OP_SECRET_KEY=A3-ZWXY7Q-K3M9PD-R8T2N-VC4HJ-LB6FW-QS5GZ\n"
	b := parse.Parse(raw, ".env")
	by := modulesOf(recognize.Recognize(b, "", module.Default))
	m, ok := by["onepassword_secret_key"]
	if !ok {
		t.Fatalf("1Password secret key not routed to module: %+v", by)
	}
	if m.Label != "OP_SECRET_KEY" {
		t.Errorf("label should be the var name, got %q", m.Label)
	}
	mod, _ := module.Default.ByName("onepassword_secret_key")
	fs, _ := mod.Recon(context.Background(), nil, module.Token{}, m.Fields)
	got := indexByKey(fs)
	if got["impact"].Flag != module.FlagForceMultiplier {
		t.Errorf("impact should be a force multiplier: %+v", got["impact"])
	}
	if got["validation"].Flag != module.FlagCantCharacterize {
		t.Errorf("validation should be can't-characterize: %+v", got["validation"])
	}
	if tier := score.TierFor(mod.Summarize("t", fs), score.Context{}); tier == score.TierInfo || tier == score.TierDead {
		t.Errorf("a leaked secret key should rank above INFO, got %s", tier)
	}
}

func TestKeePassRecognized(t *testing.T) {
	// by extension
	b := parse.Parse("ignored content", "Personal.kdbx")
	if _, ok := modulesOf(recognize.Recognize(b, "", module.Default))["keepass_db"]; !ok {
		t.Errorf("kdbx extension not recognized")
	}
	// by KDBX magic bytes, no telltale extension
	b2 := parse.Parse("\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5\x00\x04binarytail", "backup.bin")
	if _, ok := modulesOf(recognize.Recognize(b2, "", module.Default))["keepass_db"]; !ok {
		t.Errorf("kdbx magic bytes not recognized")
	}
}

func TestBitwardenEncryptedVaultRecognized(t *testing.T) {
	raw := `{"encrypted":true,"encKeyValidation_DO_NOT_EDIT":"2.aaa|bbb|ccc","items":[{"login":{"username":"2.x|y|z"}}]}`
	b := parse.Parse(raw, "bitwarden_encrypted_export.json")
	by := modulesOf(recognize.Recognize(b, "", module.Default))
	if _, ok := by["bitwarden_vault"]; !ok {
		t.Fatalf("encrypted bitwarden vault not recognized: %+v", by)
	}
	if _, ok := by["vault_export_plaintext"]; ok {
		t.Errorf("an encrypted vault must not be treated as a plaintext export")
	}
}

func TestBitwardenPlaintextExportFansOut(t *testing.T) {
	raw := `{"encrypted":false,"items":[
		{"type":1,"name":"GitHub","login":{"username":"me","password":"Gh!tHubPw2024xZ","totp":"JBSWY3DPEHPK3PXP","uris":[{"uri":"https://github.com"}]}},
		{"type":1,"name":"AWS","login":{"username":"admin","password":"Aws$ecret9KdoeL","uris":[{"uri":"https://console.aws.amazon.com"}]}},
		{"type":2,"name":"a secure note"}
	]}`
	b := parse.Parse(raw, "bitwarden_export_20240101000000.json")
	matches := recognize.Recognize(b, "", module.Default)
	by := modulesOf(matches)
	sum, ok := by["vault_export_plaintext"]
	if !ok {
		t.Fatalf("plaintext export headline missing: %+v", by)
	}
	if sum.Fields["source"] != "bitwarden" || sum.Fields["count"] != "2" {
		t.Errorf("export summary fields wrong: %+v", sum.Fields)
	}
	if sum.Fields["totp"] != "1" {
		t.Errorf("totp count wrong: %+v", sum.Fields)
	}
	var pws int
	for _, m := range matches {
		if m.Secret == "Gh!tHubPw2024xZ" || m.Secret == "Aws$ecret9KdoeL" {
			pws++
		}
	}
	if pws != 2 {
		t.Errorf("want both passwords fanned out as candidates, got %d: %+v", pws, matches)
	}
	mod, _ := module.Default.ByName("vault_export_plaintext")
	fs, _ := mod.Recon(context.Background(), nil, module.Token{}, sum.Fields)
	if got := score.TierFor(mod.Summarize("t", fs), score.Context{}); got != score.TierCritical {
		t.Errorf("a plaintext credential dump should be CRITICAL, got %s", got)
	}
}

func TestLastPassCSVExport(t *testing.T) {
	raw := "url,username,password,totp,extra,name,grouping,fav\n" +
		"https://bank.example,jdoe,Bnk!ng2024xZ,,,Bank,Finance,0\n" +
		"https://mail.example,jdoe,M@ilPass99Lo,,,Mail,,0\n"
	b := parse.Parse(raw, "lastpass_export.csv")
	by := modulesOf(recognize.Recognize(b, "", module.Default))
	sum, ok := by["vault_export_plaintext"]
	if !ok || sum.Fields["source"] != "lastpass" {
		t.Fatalf("lastpass CSV not recognized as a plaintext export: %+v", by)
	}
	if sum.Fields["count"] != "2" {
		t.Errorf("login count wrong: %+v", sum.Fields)
	}
}

func TestDashlaneCSVExport(t *testing.T) {
	raw := "username,title,password,note,url,category,otpSecret\n" +
		"jdoe,GitHub,Gh!tPass2024xy,,https://github.com,Dev,JBSWY3DPEHPK3PXP\n"
	b := parse.Parse(raw, "dashlane_export.csv")
	by := modulesOf(recognize.Recognize(b, "", module.Default))
	sum, ok := by["vault_export_plaintext"]
	if !ok || sum.Fields["source"] != "dashlane" {
		t.Fatalf("dashlane CSV not recognized as a plaintext export: %+v", by)
	}
	if sum.Fields["totp"] != "1" {
		t.Errorf("totp count wrong: %+v", sum.Fields)
	}
}

func TestBitwardenAPIKeyRecon(t *testing.T) {
	mux := http.NewServeMux()
	gotToken := false
	mux.HandleFunc("/connect/token", func(w http.ResponseWriter, r *http.Request) {
		gotToken = true
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("scope") != "api" {
			t.Errorf("grant/scope wrong: %q %q", r.Form.Get("grant_type"), r.Form.Get("scope"))
		}
		if r.Form.Get("client_id") != "user.guid-123" {
			t.Errorf("client_id not sent in body: %q", r.Form.Get("client_id"))
		}
		respond(w, `{"access_token":"BWTOKEN","token_type":"Bearer"}`)
	})
	mux.HandleFunc("/sync", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer BWTOKEN" {
			t.Errorf("sync not using exchanged token: %q", r.Header.Get("Authorization"))
		}
		respond(w, `{"profile":{"email":"dev@acme.com","organizations":[{"id":"o1","name":"Acme Inc"}]},"ciphers":[{"id":"c1"},{"id":"c2"},{"id":"c3"}]}`)
	})
	got := driveModule(t, "bitwarden", module.Fields{
		"client_id": "user.guid-123", "client_secret": "sek",
		"endpoint": "https://api.bitwarden.com", "identity": "https://identity.bitwarden.com",
	}, mux)
	if !gotToken {
		t.Error("token endpoint never called")
	}
	if got["account"].Value != "dev@acme.com" {
		t.Errorf("account email wrong: %+v", got["account"])
	}
	if got["vault items (encrypted)"].Value != "3" {
		t.Errorf("vault item count wrong: %+v", got["vault items (encrypted)"])
	}
	if got["organizations"].Flag != module.FlagWarn {
		t.Errorf("org membership not flagged: %+v", got["organizations"])
	}
}
