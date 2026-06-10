package modules

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"database/sql"
	"encoding/asn1"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
	"github.com/puck-security/geiger/internal/recon"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/crypto/pbkdf2"
)

var (
	oidPBKDF2   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidAES256   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidDESEDE3  = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}
	testEntropy = []byte("0123456789abcdefghijklmnopqrstuv")
)

func pkcs7(b []byte, bs int) []byte {
	pad := bs - len(b)%bs
	for i := 0; i < pad; i++ {
		b = append(b, byte(pad))
	}
	return b
}

// encodePBES2 builds an NSS-format PBES2 (PBKDF2-SHA256 + AES-256-CBC) blob for
// the given plaintext — the exact wire shape Firefox writes, so the test
// validates geiger's parser against a real structure (not its own inverse).
func encodePBES2(t *testing.T, globalSalt, masterPW, plaintext []byte) []byte {
	t.Helper()
	entrySalt := testEntropy[:16]
	iters := 1000
	iv14 := testEntropy[:14]
	pwHash := sha1.Sum(append(append([]byte{}, globalSalt...), masterPW...))
	key := pbkdf2.Key(pwHash[:], entrySalt, iters, 32, sha256.New)
	block, _ := aes.NewCipher(key)
	iv := append([]byte{0x04, 0x0e}, iv14...)
	ct := make([]byte, len(pkcs7(plaintext, aes.BlockSize)))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, pkcs7(plaintext, aes.BlockSize))

	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // alg
			b.AddASN1ObjectIdentifier(oidPBES2)
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // params
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // kdf
					b.AddASN1ObjectIdentifier(oidPBKDF2)
					b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
						b.AddASN1OctetString(entrySalt)
						b.AddASN1Int64(int64(iters))
					})
				})
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // enc
					b.AddASN1ObjectIdentifier(oidAES256)
					b.AddASN1OctetString(iv14)
				})
			})
		})
		b.AddASN1OctetString(ct)
	})
	out, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func encodeLoginEntry(t *testing.T, key, plaintext []byte) string {
	t.Helper()
	iv := testEntropy[:8]
	block, _ := des.NewTripleDESCipher(key)
	ct := make([]byte, len(pkcs7(plaintext, des.BlockSize)))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, pkcs7(plaintext, des.BlockSize))
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1OctetString(ckaIDMagic)
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidDESEDE3)
			b.AddASN1OctetString(iv)
		})
		b.AddASN1OctetString(ct)
	})
	out, _ := b.Bytes()
	return base64.StdEncoding.EncodeToString(out)
}

// buildFirefoxProfile writes a key4.db + logins.json (no primary password) with
// one known login, and returns the logins.json path.
func buildFirefoxProfile(t *testing.T, dir string, host, user, pass string) string {
	t.Helper()
	globalSalt := []byte("global-salt-16by")
	masterKey := make([]byte, 24)
	if _, err := rand.Read(masterKey); err != nil {
		t.Fatal(err)
	}
	item2 := encodePBES2(t, globalSalt, nil, []byte("password-check"))
	a11 := encodePBES2(t, globalSalt, nil, masterKey)

	key4 := filepath.Join(dir, "key4.db")
	db, err := sql.Open("sqlite", "file:"+key4)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`CREATE TABLE metadata (id TEXT PRIMARY KEY, item1 BLOB, item2 BLOB)`,
		`CREATE TABLE nssPrivate (a11 BLOB, a102 BLOB)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`INSERT INTO metadata (id,item1,item2) VALUES ('password',?,?)`, globalSalt, item2); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO nssPrivate (a11,a102) VALUES (?,?)`, a11, ckaIDMagic); err != nil {
		t.Fatal(err)
	}
	db.Close()

	loginsPath := filepath.Join(dir, "logins.json")
	body := `{"logins":[{"hostname":"` + host + `","encryptedUsername":"` +
		encodeLoginEntry(t, masterKey, []byte(user)) + `","encryptedPassword":"` +
		encodeLoginEntry(t, masterKey, []byte(pass)) + `"}]}`
	if err := os.WriteFile(loginsPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return loginsPath
}

func TestFirefoxOfflineDecryptRoundTrip(t *testing.T) {
	dir := t.TempDir()
	loginsPath := buildFirefoxProfile(t, dir, "https://example.com", "alice", "s3cr3t-passw0rd!")

	logins, key, err := firefoxRecover(loginsPath)
	if err != nil {
		t.Fatalf("firefoxRecover: %v", err)
	}
	if len(logins) != 1 {
		t.Fatalf("want 1 login, got %d", len(logins))
	}
	pw, err := decryptFirefoxLogin(key, logins[0].encPassword)
	if err != nil {
		t.Fatalf("decrypt password: %v", err)
	}
	if pw != "s3cr3t-passw0rd!" {
		t.Errorf("password = %q", pw)
	}
	user, _ := decryptFirefoxLogin(key, logins[0].encUsername)
	if user != "alice" {
		t.Errorf("username = %q", user)
	}
}

func TestFirefoxModuleReconAndHarvest(t *testing.T) {
	dir := t.TempDir()
	loginsPath := buildFirefoxProfile(t, dir, "https://corp.example", "svc", "Tr0ub4dour")
	mod, _ := module.Default.ByName("firefox_logins")
	fields := module.Fields{"source": loginsPath, "count": "1"}

	// not intrusive → gated, no decryption
	dry := recon.New(nil, true) // live, NOT intrusive
	fs, _ := mod.Recon(context.Background(), dry, module.Token{}, fields)
	if indexByKey(fs)["decrypt"].Flag != module.FlagCantCharacterize {
		t.Errorf("without --intrusive the store must be gated: %+v", fs)
	}

	// intrusive → decrypts + force-multiplier, with the recovered site inventoried.
	c := recon.New(nil, true)
	c.SetIntrusive(true)
	fs2, _ := mod.Recon(context.Background(), c, module.Token{}, fields)
	rec := indexByKey(fs2)["recovered"]
	if rec.Flag != module.FlagForceMultiplier {
		t.Errorf("intrusive recon should recover logins as a force multiplier: %+v", fs2)
	}
	if len(rec.Detail) != 1 || rec.Detail[0] != "corp.example" {
		t.Errorf("recovered finding should inventory the site, got Detail %v", rec.Detail)
	}

	// A web password is the loot itself — inventoried above, NOT fed back through
	// recon (where it would surface as unplaceable generic_secret noise).
	h := mod.(module.Harvester)
	got, _ := h.Harvest(context.Background(), c, module.Token{}, fields)
	if len(got) != 0 {
		t.Errorf("a web password must not be harvested for re-triage: %+v", got)
	}

	// A saved value that IS a real provider token gets harvested and re-triaged.
	dir2 := t.TempDir()
	tokenPath := buildFirefoxProfile(t, dir2, "https://github.example", "bot", "ghp_0123456789abcdefghij0123456789abcd")
	tok, _ := h.Harvest(context.Background(), c, module.Token{}, module.Fields{"source": tokenPath, "count": "1"})
	if len(tok) != 1 || tok[0].Value != "ghp_0123456789abcdefghij0123456789abcd" {
		t.Errorf("a token-shaped saved value should be harvested: %+v", tok)
	}
}

func TestFirefoxRecognizer(t *testing.T) {
	raw := `{"logins":[{"hostname":"https://x","encryptedUsername":"ME...","encryptedPassword":"MD.."}],"version":3}`
	b := parse.Parse(raw, "/home/u/.mozilla/firefox/abc.default/logins.json")
	if _, ok := modulesOf(recognize.Recognize(b, "", module.Default))["firefox_logins"]; !ok {
		t.Error("logins.json not recognized as firefox_logins")
	}
}
