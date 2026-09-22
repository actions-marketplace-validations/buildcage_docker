package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// A PKCS#12 trust store holds parsed X.509 certificates, unlike the JKS tests
// whose "DER" is a stand-in string the parser never decodes. These build real
// certificates so go-pkcs12 accepts them the way a JDK's cacerts does.
func testCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Unix(1700000000, 0),
		NotAfter:              time.Unix(1900000000, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating a certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing the certificate: %v", err)
	}
	return cert
}

// passwordlessStore is a cacerts written the way the JDK ships one: no MAC, the
// certificate bags unencrypted, so it opens under the empty password.
func passwordlessStore(t *testing.T, certs ...*x509.Certificate) []byte {
	t.Helper()
	data, err := pkcs12.Passwordless.EncodeTrustStore(certs, "")
	if err != nil {
		t.Fatalf("encoding a trust store: %v", err)
	}
	return data
}

func mustWritePKCS12(t *testing.T, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cacerts")
	mustWriteFileBytes(t, path, content)
	return path
}

func mustWriteFileBytes(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

// A JDK's own cacerts carries no MAC, so it decodes under the empty password
// even though it is nominally "changeit"-sealed. This is the property the whole
// PKCS#12 path rests on.
func TestDecodePKCS12EmptyPassword(t *testing.T) {
	ca := testCert(t, "buildcage")
	root := testCert(t, "digicert")
	store := passwordlessStore(t, root, ca)

	certs, err := decodePKCS12(store)
	if err != nil {
		t.Fatalf("decoding under the empty password: %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("decoded %d certificates, want 2", len(certs))
	}
}

func TestRemoveFromPKCS12(t *testing.T) {
	ca := testCert(t, "buildcage")
	root := testCert(t, "digicert")
	path := mustWritePKCS12(t, passwordlessStore(t, root, ca))

	rewritten, err := removeFromPKCS12(path, [][]byte{ca.Raw})
	if err != nil {
		t.Fatalf("removing the CA: %v", err)
	}
	if !rewritten {
		t.Fatal("removeFromPKCS12 reported no rewrite")
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(content, ca.Raw) {
		t.Error("the CA's DER is still in the rewritten keystore")
	}
	certs, err := decodePKCS12(content)
	if err != nil {
		t.Fatalf("the rewritten keystore no longer decodes: %v", err)
	}
	if len(certs) != 1 || certs[0].Subject.CommonName != "digicert" {
		t.Errorf("the rewrite left %d certificates, want only digicert", len(certs))
	}
}

// Not a PKCS#12 at all, or one the empty password will not open: both leave the
// file alone with (false, nil) for the caller to report as unstrippable.
func TestRemoveFromPKCS12LeavesOthersAlone(t *testing.T) {
	ca := testCert(t, "buildcage")
	cases := map[string][]byte{
		"a JKS keystore":            {0xfe, 0xed, 0xfe, 0xed, 0x00},
		"a bare DER among bytes":    append([]byte{0x30, 0x82}, ca.Raw...),
		"something else entirely":   []byte("not a keystore at all"),
		"a password-sealed PKCS#12": encryptedStore(t, ca),
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			path := mustWritePKCS12(t, content)
			before, _ := os.ReadFile(path)
			rewritten, err := removeFromPKCS12(path, [][]byte{ca.Raw})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if rewritten {
				t.Error("reported a rewrite it should not have made")
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(before, after) {
				t.Error("the file was changed")
			}
		})
	}
}

// encryptedStore is a Modern trust store: its certificate bags are PBES2
// encrypted under a real password, so the empty-password decode this uses
// cannot open it. It stands in for a keystore a step replaced with one of its
// own that this cannot rewrite.
func encryptedStore(t *testing.T, certs ...*x509.Certificate) []byte {
	t.Helper()
	data, err := pkcs12.Modern.EncodeTrustStore(certs, "a-real-password")
	if err != nil {
		t.Fatalf("encoding an encrypted trust store: %v", err)
	}
	return data
}

// The DER a scan matched is in the file's bytes but not as a decoded trusted
// certificate: nothing is removed and the caller is left to report it.
func TestRemoveFromPKCS12CertNotAmongEntries(t *testing.T) {
	root := testCert(t, "digicert")
	ca := testCert(t, "buildcage")
	// A store of digicert only, but asked to strip the ca. go-pkcs12 finds no
	// matching entry, so nothing is rewritten.
	path := mustWritePKCS12(t, passwordlessStore(t, root))

	rewritten, err := removeFromPKCS12(path, [][]byte{ca.Raw})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rewritten {
		t.Error("rewrote a keystore that did not hold the CA")
	}
}

func TestRemoveFromPKCS12TooLarge(t *testing.T) {
	ca := testCert(t, "buildcage")
	t.Cleanup(func(prev int64) func() {
		return func() { maxKeystoreBytes = prev }
	}(maxKeystoreBytes))
	maxKeystoreBytes = 8
	path := mustWritePKCS12(t, passwordlessStore(t, ca))

	rewritten, err := removeFromPKCS12(path, [][]byte{ca.Raw})
	if err != nil || rewritten {
		t.Fatalf("a keystore past the size cap should be left alone: rewritten=%v err=%v", rewritten, err)
	}
}

func TestRemoveFromPKCS12NotThere(t *testing.T) {
	ca := testCert(t, "buildcage")
	_, err := removeFromPKCS12(filepath.Join(t.TempDir(), "absent"), [][]byte{ca.Raw})
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("want a not-exist error, got %v", err)
	}
}

// The sweep reaches removeFromPKCS12 through stripCA: a PKCS#12 cacerts holding
// the CA is rewritten rather than failing the build as it did before.
func TestStripCARewritesPKCS12(t *testing.T) {
	ca := testCert(t, "buildcage")
	root := testCert(t, "digicert")
	caPEM := certPEM(ca)
	path := mustWritePKCS12(t, passwordlessStore(t, root, ca))

	left, err := stripCA(path, caPEM, certificateDERs(caPEM))
	if err != nil {
		t.Fatalf("stripCA: %v", err)
	}
	if left {
		t.Error("stripCA left the CA in a PKCS#12 keystore it can rewrite")
	}
}

func certPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// A file shaped like a PKCS#12 (the 0x30 0x82 opening) that carries the CA's
// DER in the clear but will not decode: the DER is found, neither keystore
// rewrite reaches it, and stripCA reports it left rather than passing the
// build. This is the fail-closed the Q2 decision asks for, reached only because
// the DER is actually present. An encrypted store hides the DER instead, so it
// is never a strip candidate in the first place (see the LeavesOthersAlone
// case), which is the same decision from the other side.
func TestStripCAUnstrippableWhenUndecodable(t *testing.T) {
	ca := testCert(t, "buildcage")
	caPEM := certPEM(ca)
	undecodable := append(slices.Clone(pkcs12Magic), ca.Raw...)
	path := mustWritePKCS12(t, undecodable)

	left, err := stripCA(path, caPEM, certificateDERs(caPEM))
	if err != nil {
		t.Fatalf("stripCA: %v", err)
	}
	if !left {
		t.Error("stripCA cleared a keystore it cannot decode though the DER is present")
	}
}

// The I/O error branches, exercised the way the JKS tests exercise
// removeFromKeystore's: a real file opened through a stub that fails one
// operation partway, so the code meets a half-finished file.
func TestRemoveFromPKCS12StatFails(t *testing.T) {
	ca := testCert(t, "buildcage")
	path := mustWritePKCS12(t, passwordlessStore(t, ca))
	useBrokenBundleFile(t, &brokenFile{failStat: true})
	if _, err := removeFromPKCS12(path, [][]byte{ca.Raw}); !errors.Is(err, errBrokenFile) {
		t.Fatalf("want the stat failure, got %v", err)
	}
}

func TestRemoveFromPKCS12ReadFails(t *testing.T) {
	ca := testCert(t, "buildcage")
	path := mustWritePKCS12(t, passwordlessStore(t, ca))
	useBrokenBundleFile(t, &brokenFile{failReadAt: 1})
	if _, err := removeFromPKCS12(path, [][]byte{ca.Raw}); !errors.Is(err, errBrokenFile) {
		t.Fatalf("want the read failure, got %v", err)
	}
}

func TestRemoveFromPKCS12WriteFails(t *testing.T) {
	ca := testCert(t, "buildcage")
	root := testCert(t, "digicert")
	path := mustWritePKCS12(t, passwordlessStore(t, root, ca))
	useBrokenBundleFile(t, &brokenFile{failWriteAt: 1})
	if _, err := removeFromPKCS12(path, [][]byte{ca.Raw}); !errors.Is(err, errBrokenFile) {
		t.Fatalf("want the write failure, got %v", err)
	}
}

// stripCA hands a removeFromPKCS12 error back rather than swallowing it: a write
// that fails mid-rewrite leaves the layer possibly still carrying the CA, so the
// build must not proceed.
func TestStripCAPropagatesPKCS12Error(t *testing.T) {
	ca := testCert(t, "buildcage")
	root := testCert(t, "digicert")
	caPEM := certPEM(ca)
	path := mustWritePKCS12(t, passwordlessStore(t, root, ca))
	useBrokenBundleFile(t, &brokenFile{failWriteAt: 1})
	if _, err := stripCA(path, caPEM, certificateDERs(caPEM)); !errors.Is(err, errBrokenFile) {
		t.Fatalf("want the write failure propagated, got %v", err)
	}
}

// The encode-error branch: valid certificates under the empty password never
// make Passwordless.EncodeTrustStore fail, so the seam is stubbed to prove the
// error is handed back rather than a truncated keystore being written.
func TestRemoveFromPKCS12EncodeFails(t *testing.T) {
	ca := testCert(t, "buildcage")
	root := testCert(t, "digicert")
	path := mustWritePKCS12(t, passwordlessStore(t, root, ca))
	old := encodePKCS12
	encodePKCS12 = func([]*x509.Certificate) ([]byte, error) { return nil, errBrokenFile }
	t.Cleanup(func() { encodePKCS12 = old })
	if _, err := removeFromPKCS12(path, [][]byte{ca.Raw}); !errors.Is(err, errBrokenFile) {
		t.Fatalf("want the encode failure, got %v", err)
	}
}
