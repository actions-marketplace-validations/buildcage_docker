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

func certPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func mustWritePKCS12(t *testing.T, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cacerts")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
	return path
}

// A JDK's own cacerts carries no MAC, so it decodes under the empty password
// even though it is nominally "changeit"-sealed. This is the property the whole
// PKCS#12 path rests on.
func TestDecodePKCS12EmptyPassword(t *testing.T) {
	ca := testCert(t, "buildcage")
	root := testCert(t, "digicert")
	certs, err := decodePKCS12(passwordlessStore(t, root, ca))
	if err != nil {
		t.Fatalf("decoding under the empty password: %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("decoded %d certificates, want 2", len(certs))
	}
}

func TestPKCS12Without(t *testing.T) {
	ca := testCert(t, "buildcage")
	root := testCert(t, "digicert")
	out, removed, err := pkcs12Without(passwordlessStore(t, root, ca), [][]byte{ca.Raw})
	if err != nil || !removed {
		t.Fatalf("removing the CA: removed=%v err=%v", removed, err)
	}
	if bytes.Contains(out, ca.Raw) {
		t.Error("the CA's DER is still in the rewritten keystore")
	}
	certs, err := decodePKCS12(out)
	if err != nil {
		t.Fatalf("the rewritten keystore no longer decodes: %v", err)
	}
	if len(certs) != 1 || certs[0].Subject.CommonName != "digicert" {
		t.Errorf("the rewrite left %d certificates, want only digicert", len(certs))
	}
}

// A store that will not open under the empty password is one this cannot
// rewrite: it removes nothing and leaves the caller to report it.
func TestPKCS12WithoutUndecodable(t *testing.T) {
	ca := testCert(t, "buildcage")
	for name, content := range map[string][]byte{
		"a Modern encrypted store": encryptedStore(t, ca),
		"pkcs12-shaped garbage":    append([]byte{0x30, 0x82}, ca.Raw...),
	} {
		t.Run(name, func(t *testing.T) {
			out, removed, err := pkcs12Without(content, [][]byte{ca.Raw})
			if err != nil || removed || out != nil {
				t.Fatalf("want (nil,false,nil), got (%v,%v,%v)", out, removed, err)
			}
		})
	}
}

// The DER a scan matched is in the file's bytes but not as a decoded trusted
// certificate: nothing is removed and the caller is left to report it.
func TestPKCS12WithoutCertNotAmongEntries(t *testing.T) {
	root := testCert(t, "digicert")
	ca := testCert(t, "buildcage")
	out, removed, err := pkcs12Without(passwordlessStore(t, root), [][]byte{ca.Raw})
	if err != nil || removed || out != nil {
		t.Fatalf("want (nil,false,nil), got (%v,%v,%v)", out, removed, err)
	}
}

// The encode-error branch: valid certificates under the empty password never
// make Passwordless.EncodeTrustStore fail, so the seam is stubbed to prove the
// error is handed back rather than a truncated keystore being written.
func TestPKCS12WithoutEncodeFails(t *testing.T) {
	ca := testCert(t, "buildcage")
	root := testCert(t, "digicert")
	old := encodePKCS12
	encodePKCS12 = func([]*x509.Certificate) ([]byte, error) { return nil, errBrokenFile }
	t.Cleanup(func() { encodePKCS12 = old })
	if _, _, err := pkcs12Without(passwordlessStore(t, root, ca), [][]byte{ca.Raw}); !errors.Is(err, errBrokenFile) {
		t.Fatalf("want the encode failure, got %v", err)
	}
}

// Removing the last certificate is not an error: the empty store re-encodes and
// decodes cleanly and carries no DER, so the sweep passes rather than leaving an
// unreadable keystore behind.
func TestPKCS12WithoutRemovesLastCert(t *testing.T) {
	ca := testCert(t, "buildcage")
	out, removed, err := pkcs12Without(passwordlessStore(t, ca), [][]byte{ca.Raw})
	if err != nil || !removed {
		t.Fatalf("removing the only cert: removed=%v err=%v", removed, err)
	}
	certs, err := decodePKCS12(out)
	if err != nil {
		t.Fatalf("the emptied keystore no longer decodes: %v", err)
	}
	if len(certs) != 0 {
		t.Errorf("the emptied keystore still holds %d certificates", len(certs))
	}
}

// removeFromKeystore reads the file once and dispatches on its magic: a PKCS#12
// keystore holding the CA is rewritten in place, the gap that used to fail the
// build.
func TestRemoveFromKeystoreStripsPKCS12(t *testing.T) {
	ca := testCert(t, "buildcage")
	root := testCert(t, "digicert")
	path := mustWritePKCS12(t, passwordlessStore(t, root, ca))
	rewritten, err := removeFromKeystore(path, [][]byte{ca.Raw})
	if err != nil || !rewritten {
		t.Fatalf("rewriting the PKCS#12 keystore: rewritten=%v err=%v", rewritten, err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(content, ca.Raw) {
		t.Error("the CA's DER is still in the file on disk")
	}
}

// A PKCS#12 keystore that does not hold the CA is left untouched, reported as no
// rewrite the same way a non-keystore file is.
func TestRemoveFromKeystorePKCS12NotHolding(t *testing.T) {
	root := testCert(t, "digicert")
	ca := testCert(t, "buildcage")
	path := mustWritePKCS12(t, passwordlessStore(t, root))
	before, _ := os.ReadFile(path)
	rewritten, err := removeFromKeystore(path, [][]byte{ca.Raw})
	if err != nil || rewritten {
		t.Fatalf("want no rewrite, got rewritten=%v err=%v", rewritten, err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Error("the file was changed")
	}
}

// removeFromKeystore hands a PKCS#12 rewrite error back rather than reporting
// no rewrite, so the caller does not read a failed strip as a clean one.
func TestRemoveFromKeystorePKCS12Error(t *testing.T) {
	ca := testCert(t, "buildcage")
	root := testCert(t, "digicert")
	path := mustWritePKCS12(t, passwordlessStore(t, root, ca))
	old := encodePKCS12
	encodePKCS12 = func([]*x509.Certificate) ([]byte, error) { return nil, errBrokenFile }
	t.Cleanup(func() { encodePKCS12 = old })
	if _, err := removeFromKeystore(path, [][]byte{ca.Raw}); !errors.Is(err, errBrokenFile) {
		t.Fatalf("want the encode failure, got %v", err)
	}
}

// The sweep reaches the PKCS#12 rewrite through stripCA: a PKCS#12 cacerts
// holding the CA is stripped rather than failing the build as it did before.
func TestStripCARewritesPKCS12(t *testing.T) {
	ca := testCert(t, "buildcage")
	root := testCert(t, "digicert")
	caPEM := certPEM(ca)
	path := mustWritePKCS12(t, passwordlessStore(t, root, ca))
	left, err := stripCA(path, caPEM, caMarksOf(caPEM))
	if err != nil {
		t.Fatalf("stripCA: %v", err)
	}
	if left {
		t.Error("stripCA left the CA in a PKCS#12 keystore it can rewrite")
	}
}

// A file shaped like a PKCS#12 that carries the CA's DER in the clear but will
// not decode: the DER is found, the keystore rewrite cannot reach it, and
// stripCA reports it left rather than passing the build. It fails closed only
// because the DER is actually present; an encrypted store hides the DER instead,
// so it is never a strip candidate.
func TestStripCAUnstrippableWhenUndecodable(t *testing.T) {
	ca := testCert(t, "buildcage")
	caPEM := certPEM(ca)
	path := mustWritePKCS12(t, append([]byte{0x30, 0x82}, ca.Raw...))
	left, err := stripCA(path, caPEM, caMarksOf(caPEM))
	if err != nil {
		t.Fatalf("stripCA: %v", err)
	}
	if !left {
		t.Error("stripCA cleared a keystore it cannot decode though the DER is present")
	}
}

// stripCA hands a rewrite error back rather than swallowing it: a write that
// fails mid-rewrite leaves the layer possibly still carrying the CA, so the
// build must not proceed.
func TestStripCAPropagatesPKCS12Error(t *testing.T) {
	ca := testCert(t, "buildcage")
	root := testCert(t, "digicert")
	caPEM := certPEM(ca)
	path := mustWritePKCS12(t, passwordlessStore(t, root, ca))
	useBrokenBundleFile(t, &brokenFile{failWriteAt: 1})
	if _, err := stripCA(path, caPEM, caMarksOf(caPEM)); !errors.Is(err, errBrokenFile) {
		t.Fatalf("want the write failure propagated, got %v", err)
	}
}

// pkcs12With adds a trusted certificate to a passwordless store, leaving it
// decodable and holding the added cert alongside the ones it had.
func TestPKCS12With(t *testing.T) {
	root := testCert(t, "digicert")
	ca := testCert(t, "buildcage")
	out, err := pkcs12With(passwordlessStore(t, root), [][]byte{ca.Raw})
	if err != nil {
		t.Fatalf("pkcs12With: %v", err)
	}
	certs, err := decodePKCS12(out)
	if err != nil {
		t.Fatalf("the injected store no longer decodes: %v", err)
	}
	names := map[string]bool{}
	for _, c := range certs {
		names[c.Subject.CommonName] = true
	}
	if !names["digicert"] || !names["buildcage"] {
		t.Errorf("injected store holds %v, want both digicert and buildcage", names)
	}
}

// A store the empty password will not open cannot be injected into.
func TestPKCS12WithUndecodable(t *testing.T) {
	ca := testCert(t, "buildcage")
	if _, err := pkcs12With(encryptedStore(t, ca), [][]byte{ca.Raw}); err == nil {
		t.Fatal("want a decode error for an encrypted store")
	}
}

// The DER handed in has to be a certificate; anything else is reported rather
// than written into the store.
func TestPKCS12WithRejectsBadDER(t *testing.T) {
	root := testCert(t, "digicert")
	if _, err := pkcs12With(passwordlessStore(t, root), [][]byte{[]byte("not a certificate")}); err == nil {
		t.Fatal("want a parse error for a non-certificate DER")
	}
}

// testIssuer is a CA that can sign, standing in for the proxy's: what a step
// saves from a server is a certificate this issued, not this one. nonce is the
// random serialNumber each proxy CA's subject carries.
func testIssuer(t *testing.T, nonce string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{CommonName: "buildcage proxy CA", SerialNumber: nonce},
		NotBefore:             time.Unix(1700000000, 0),
		NotAfter:              time.Unix(1900000000, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating the CA: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing the CA: %v", err)
	}
	return cert, key
}

// testLeaf is a server certificate for host, issued by ca the way the proxy
// forges one. The key goes with it for a keystore that needs one.
func testLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, host string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(8),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Unix(1700000000, 0),
		NotAfter:     time.Unix(1900000000, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("creating the leaf: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing the leaf: %v", err)
	}
	return cert, key
}

func mustEncodeTrustStore(t *testing.T, enc *pkcs12.Encoder, password string, certs ...*x509.Certificate) []byte {
	t.Helper()
	data, err := enc.EncodeTrustStore(certs, password)
	if err != nil {
		t.Fatalf("encoding a trust store: %v", err)
	}
	return data
}

// A PKCS#12 keystore that encrypts its bags hides the DER from the byte scan,
// so the ones that open under a password this tries are opened and read. Both
// shapes the library decodes are covered: a trust store, which is what keytool
// -importkeystore makes of a cacerts, and a key with its chain.
func TestFileHoldsCAReadsAnEncryptedPKCS12ItCanOpen(t *testing.T) {
	ca, caKey := testIssuer(t, "this run")
	root := testCert(t, "digicert")
	leaf, leafKey := testLeaf(t, ca, caKey, "app.example")
	chain := func(password string) []byte {
		data, err := pkcs12.Modern.Encode(leafKey, leaf, []*x509.Certificate{ca}, password)
		if err != nil {
			t.Fatalf("encoding a keystore: %v", err)
		}
		return data
	}
	marks := caMarksOf(certPEM(ca))

	for name, content := range map[string][]byte{
		"a trust store under changeit":        mustEncodeTrustStore(t, pkcs12.Modern, keystorePassword, root, ca),
		"a trust store under no password":     mustEncodeTrustStore(t, pkcs12.Modern, "", root, ca),
		"a key and chain under changeit":      chain(keystorePassword),
		"a trust store holding a forged leaf": mustEncodeTrustStore(t, pkcs12.Modern, keystorePassword, root, leaf),
	} {
		t.Run(name, func(t *testing.T) {
			if bytes.Contains(content, ca.Raw) {
				t.Fatal("the fixture holds the DER in the clear, so it would not test the decryption")
			}
			found, err := fileHoldsCA(mustWritePKCS12(t, content), marks.needles)
			if err != nil {
				t.Fatalf("fileHoldsCA: %v", err)
			}
			if !found {
				t.Error("an encrypted keystore holding the CA passed")
			}
		})
	}
}

// What cannot be opened, or opens to nothing of the CA's, passes: dependencies
// ship encrypted test keystores of their own, and those are not the CA's.
func TestFileHoldsCAPassesAnEncryptedPKCS12WithoutTheCA(t *testing.T) {
	ca, _ := testIssuer(t, "this run")
	other, otherKey := testIssuer(t, "another run")
	leaf, leafKey := testLeaf(t, other, otherKey, "app.example")
	withKey, err := pkcs12.Modern.Encode(leafKey, leaf, []*x509.Certificate{other}, keystorePassword)
	if err != nil {
		t.Fatalf("encoding a keystore: %v", err)
	}
	marks := caMarksOf(certPEM(ca))

	for name, content := range map[string][]byte{
		"the CA under a password of its own": mustEncodeTrustStore(t, pkcs12.Modern, "a-real-password", ca),
		"another CA under changeit":          mustEncodeTrustStore(t, pkcs12.Modern, keystorePassword, other),
		"a key and chain of another CA":      withKey,
	} {
		t.Run(name, func(t *testing.T) {
			found, err := fileHoldsCA(mustWritePKCS12(t, content), marks.needles)
			if err != nil {
				t.Fatalf("fileHoldsCA: %v", err)
			}
			if found {
				t.Error("an encrypted keystore without a readable copy of the CA failed")
			}
		})
	}
}

// Past the size a keystore reaches, the file is not read in to be decoded.
func TestSealedPKCS12HoldsSkipsAnOversizedFile(t *testing.T) {
	ca, _ := testIssuer(t, "this run")
	content := mustEncodeTrustStore(t, pkcs12.Modern, keystorePassword, ca)
	old := maxKeystoreBytes
	maxKeystoreBytes = int64(len(content)) - 1
	t.Cleanup(func() { maxKeystoreBytes = old })
	found, err := sealedPKCS12Holds(bytes.NewReader(content), int64(len(content)), caMarksOf(certPEM(ca)).needles)
	if err != nil || found {
		t.Fatalf("got found=%v err=%v, want the file left unread", found, err)
	}
}

func TestSealedPKCS12HoldsReportsAFailedRead(t *testing.T) {
	ca, _ := testIssuer(t, "this run")
	path := mustWritePKCS12(t, mustEncodeTrustStore(t, pkcs12.Modern, keystorePassword, ca))
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("opening %s: %v", path, err)
	}
	defer f.Close()
	broken := &brokenFile{bundleFile: f, failReadAt: 1}
	if _, err := sealedPKCS12Holds(broken, 16, caMarksOf(certPEM(ca)).needles); !errors.Is(err, errBrokenFile) {
		t.Fatalf("want the read failure, got %v", err)
	}
}

// One it can open but cannot rewrite, because it is sealed under changeit, is
// reported as left rather than passed.
func TestStripCAReportsAnEncryptedPKCS12ItCannotRewrite(t *testing.T) {
	ca, _ := testIssuer(t, "this run")
	root := testCert(t, "digicert")
	caPEM := certPEM(ca)
	path := mustWritePKCS12(t, mustEncodeTrustStore(t, pkcs12.Modern, keystorePassword, root, ca))
	left, err := stripCA(path, caPEM, caMarksOf(caPEM))
	if err != nil {
		t.Fatalf("stripCA: %v", err)
	}
	if !left {
		t.Error("stripCA cleared a changeit-sealed keystore it cannot rewrite")
	}
}
