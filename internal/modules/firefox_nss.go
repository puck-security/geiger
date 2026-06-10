package modules

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"database/sql"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/crypto/pbkdf2"
)

// Firefox/NSS offline decryption of saved logins. Firefox stores the login
// ciphertext in logins.json and the master key in key4.db (an NSS SQLite key
// store). When NO primary password is set — the common case — the master key is
// derivable from key4.db's salt alone, so logins.json decrypts OFFLINE from the
// two files with no OS/keychain calls. (Chromium, by contrast, wraps its values
// with an OS keychain key and is out of scope.) Algorithm mirrors the documented
// NSS scheme: PBES2/PBKDF2-SHA256 + AES-256-CBC for a modern key4.db, the Mozilla
// SHA1/3DES PBE for a legacy one, then DES-EDE3-CBC per login entry.

var (
	oidPBES2     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBE3DES   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 5, 1, 3} // pbeWithSha1AndTripleDES-CBC
	ckaIDMagic   = []byte{0xf8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	errPrimaryPW = errors.New("firefox: primary password set or unsupported key4.db (cannot decrypt offline)")
)

// firefoxMasterKey reads key4.db and returns the DES-EDE3 master key used to
// decrypt logins.json. It only succeeds when there is no primary password.
func firefoxMasterKey(key4Path string) ([]byte, error) {
	db, err := sql.Open("sqlite", "file:"+key4Path+"?mode=ro&_pragma=query_only(1)")
	if err != nil {
		return nil, err
	}
	defer db.Close()

	var globalSalt, item2 []byte
	if err := db.QueryRow(`SELECT item1, item2 FROM metadata WHERE id = 'password'`).Scan(&globalSalt, &item2); err != nil {
		return nil, fmt.Errorf("firefox: no password metadata: %w", err)
	}
	// Validate the (empty) primary password: the metadata check value must
	// decrypt to "password-check".
	check, err := decryptPBE(globalSalt, nil, item2)
	if err != nil || !bytes.HasPrefix(check, []byte("password-check")) {
		return nil, errPrimaryPW
	}
	var a11 []byte
	if err := db.QueryRow(`SELECT a11 FROM nssPrivate WHERE a102 = ?`, ckaIDMagic).Scan(&a11); err != nil {
		return nil, fmt.Errorf("firefox: no key in nssPrivate: %w", err)
	}
	keyMaterial, err := decryptPBE(globalSalt, nil, a11)
	if err != nil {
		return nil, err
	}
	if len(keyMaterial) < 24 {
		return nil, errors.New("firefox: short master key")
	}
	return keyMaterial[:24], nil
}

// decryptPBE dispatches on the encoded algorithm (PBES2/AES vs legacy SHA1/3DES)
// and returns the decrypted value.
func decryptPBE(globalSalt, masterPW, der []byte) ([]byte, error) {
	in := cryptobyte.String(der)
	var seq cryptobyte.String
	if !in.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return nil, errors.New("firefox: bad PBE structure")
	}
	var algSeq cryptobyte.String
	if !seq.ReadASN1(&algSeq, cbasn1.SEQUENCE) {
		return nil, errors.New("firefox: bad PBE algorithm")
	}
	var algOID asn1.ObjectIdentifier
	if !algSeq.ReadASN1ObjectIdentifier(&algOID) {
		return nil, errors.New("firefox: bad PBE OID")
	}
	var ct cryptobyte.String
	if !seq.ReadASN1(&ct, cbasn1.OCTET_STRING) {
		// the ciphertext may live inside the alg params (PBES2) — re-read below
		ct = nil
	}
	switch {
	case algOID.Equal(oidPBES2):
		return decryptPBES2(globalSalt, masterPW, algSeq, []byte(ct))
	case algOID.Equal(oidPBE3DES):
		return decryptMoz3DES(globalSalt, masterPW, algSeq, []byte(ct))
	}
	return nil, fmt.Errorf("firefox: unsupported PBE algorithm %v", algOID)
}

// decryptPBES2 implements PBKDF2-HMAC-SHA256 + AES-256-CBC. params is the
// remaining PBES2 AlgorithmIdentifier content (after the OID); ct is the outer
// ciphertext OCTET STRING.
func decryptPBES2(globalSalt, masterPW []byte, params cryptobyte.String, ct []byte) ([]byte, error) {
	var p cryptobyte.String
	if !params.ReadASN1(&p, cbasn1.SEQUENCE) { // PBES2-params
		return nil, errors.New("firefox: bad PBES2 params")
	}
	// keyDerivationFunc: SEQUENCE { OID PBKDF2, SEQUENCE { salt, iters, [keyLen], [prf] } }
	var kdf cryptobyte.String
	var kdfOID asn1.ObjectIdentifier
	if !p.ReadASN1(&kdf, cbasn1.SEQUENCE) || !kdf.ReadASN1ObjectIdentifier(&kdfOID) {
		return nil, errors.New("firefox: bad KDF")
	}
	var kdfParams, salt cryptobyte.String
	var iters int
	if !kdf.ReadASN1(&kdfParams, cbasn1.SEQUENCE) ||
		!kdfParams.ReadASN1(&salt, cbasn1.OCTET_STRING) ||
		!kdfParams.ReadASN1Integer(&iters) {
		return nil, errors.New("firefox: bad PBKDF2 params")
	}
	// encryptionScheme: SEQUENCE { OID aes256-cbc, OCTET STRING iv(14) }
	var enc, ivVal cryptobyte.String
	var encOID asn1.ObjectIdentifier
	if !p.ReadASN1(&enc, cbasn1.SEQUENCE) || !enc.ReadASN1ObjectIdentifier(&encOID) ||
		!enc.ReadASN1(&ivVal, cbasn1.OCTET_STRING) {
		return nil, errors.New("firefox: bad encryption scheme")
	}
	// NSS quirk: the AES IV is the DER-encoded OCTET STRING of the 14-byte value
	// (tag 0x04 + length + value), giving a 16-byte IV.
	iv := append([]byte{0x04, byte(len(ivVal))}, []byte(ivVal)...)
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("firefox: unexpected IV length %d", len(iv))
	}
	pwHash := sha1.Sum(append(append([]byte{}, globalSalt...), masterPW...))
	key := pbkdf2.Key(pwHash[:], []byte(salt), iters, 32, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cbcDecrypt(block, iv, ct)
}

// decryptMoz3DES implements Mozilla's legacy SHA1/3DES PBE.
func decryptMoz3DES(globalSalt, masterPW []byte, params cryptobyte.String, ct []byte) ([]byte, error) {
	var p, entrySalt cryptobyte.String
	if !params.ReadASN1(&p, cbasn1.SEQUENCE) || !p.ReadASN1(&entrySalt, cbasn1.OCTET_STRING) {
		return nil, errors.New("firefox: bad 3DES params")
	}
	es := []byte(entrySalt)
	hp := sha1.Sum(append(append([]byte{}, globalSalt...), masterPW...))
	// pes = entrySalt left-padded? NSS uses entrySalt padded with leading zeros to 20.
	pes := make([]byte, 20)
	copy(pes[20-min(len(es), 20):], es)
	chpIn := append(append([]byte{}, hp[:]...), es...)
	chp := sha1.Sum(chpIn)
	mac := func(msg []byte) []byte {
		m := hmac.New(sha1.New, chp[:])
		m.Write(msg)
		return m.Sum(nil)
	}
	k1 := mac(append(append([]byte{}, pes...), es...))
	tk := mac(pes)
	k2 := mac(append(append([]byte{}, tk...), es...))
	k := append(append([]byte{}, k1...), k2...) // 40 bytes
	key := k[:24]
	iv := k[len(k)-8:]
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	return cbcDecrypt(block, iv, ct)
}

// decryptFirefoxLogin decrypts one logins.json field (base64 of an ASN.1
// SEQUENCE { keyId, SEQUENCE { OID des-ede3-cbc, iv(8) }, ciphertext }).
func decryptFirefoxLogin(key []byte, b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}
	in := cryptobyte.String(raw)
	var seq, keyID, algSeq, iv, ct cryptobyte.String
	if !in.ReadASN1(&seq, cbasn1.SEQUENCE) ||
		!seq.ReadASN1(&keyID, cbasn1.OCTET_STRING) ||
		!seq.ReadASN1(&algSeq, cbasn1.SEQUENCE) {
		return "", errors.New("firefox: bad login entry")
	}
	var algOID asn1.ObjectIdentifier
	if !algSeq.ReadASN1ObjectIdentifier(&algOID) || !algSeq.ReadASN1(&iv, cbasn1.OCTET_STRING) {
		return "", errors.New("firefox: bad login alg")
	}
	if !seq.ReadASN1(&ct, cbasn1.OCTET_STRING) {
		return "", errors.New("firefox: bad login ciphertext")
	}
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return "", err
	}
	pt, err := cbcDecrypt(block, []byte(iv), []byte(ct))
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// cbcDecrypt runs CBC decryption and strips PKCS#7 padding.
func cbcDecrypt(block cipher.Block, iv, ct []byte) ([]byte, error) {
	if len(ct) == 0 || len(ct)%block.BlockSize() != 0 || len(iv) != block.BlockSize() {
		return nil, errors.New("firefox: bad ciphertext/iv length")
	}
	out := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ct)
	pad := int(out[len(out)-1])
	if pad < 1 || pad > block.BlockSize() || pad > len(out) {
		return out, nil // unpadded / not PKCS7 — return as-is (caller validates)
	}
	return out[:len(out)-pad], nil
}
