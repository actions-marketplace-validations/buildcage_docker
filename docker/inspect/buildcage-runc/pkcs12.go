package main

// PKCS#12 is the other shape a JVM keystore comes in: newer JDKs ship
// $JAVA_HOME/lib/security/cacerts as a PKCS#12 trust store rather than the JKS
// older ones use, and keystore.type defaults to pkcs12 from JDK 9 on. The DER
// sits among the container's own bytes the same way it does in a JKS, so no PEM
// removal reaches it, and until this the sweep could detect a copy there but not
// take it out, which failed the build (errUnstrippableCA).
//
// The JDK's own cacerts carries no MAC (the password guards only the MAC, and
// the certificate bags are never encrypted), so it decodes under the empty
// password even though it is nominally sealed with "changeit". It is written
// back the same way: Passwordless, whose certificate bags are unencrypted and
// which carries no MAC, is the one shape the JVM's default loader trusts as a
// cacerts. The Modern encoders encrypt the bags with PBES2, which that loader
// does not decrypt, leaving it trusting nothing.

import (
	"bytes"
	"crypto/x509"
	"io"
	"os"
	"slices"
	"syscall"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// A PKCS#12 file is a DER SEQUENCE, so it opens with the tag 0x30 followed by a
// long-form length (0x82 for the two length bytes a keystore's size needs).
// This only steers which decoder is tried; the decode itself is what confirms
// the bytes really are a trust store.
var pkcs12Magic = []byte{0x30, 0x82}

// decodePKCS12 reads the trusted certificates out of a JDK trust store under
// the empty password. See the file comment for why that is the right password.
func decodePKCS12(content []byte) ([]*x509.Certificate, error) {
	return pkcs12.DecodeTrustStore(content, "")
}

// encodePKCS12 writes certs back as a passwordless trust store, the only shape
// the JVM's default cacerts loader trusts. See the file comment. It is a var so
// a test can make the encode fail, which valid certificates under the empty
// password otherwise never do.
var encodePKCS12 = func(certs []*x509.Certificate) ([]byte, error) {
	return pkcs12.Passwordless.EncodeTrustStore(certs, "")
}

// removeFromPKCS12 takes the certificate out of a PKCS#12 keystore, rewriting
// it in place, and reports whether it rewrote anything. It mirrors
// removeFromKeystore's contract: a file that is not a PKCS#12 trust store, or
// one that will not open under the empty password, is left alone with
// (false, nil) for the caller to report as unstrippable; the sweep only reaches
// here when the certificate is already known to be in the file, so leaving one
// it cannot open fails the build rather than passing it silently.
func removeFromPKCS12(path string, ders [][]byte) (bool, error) {
	f, err := openBundle(path, os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return false, asNotRegular(path, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return false, err
	}
	size := info.Size()
	if size < int64(len(pkcs12Magic)) || size > maxKeystoreBytes {
		return false, nil
	}
	content := make([]byte, size)
	if _, err := f.ReadAt(content, 0); err != nil && err != io.EOF {
		return false, err
	}
	if !bytes.HasPrefix(content, pkcs12Magic) {
		return false, nil
	}

	certs, err := decodePKCS12(content)
	if err != nil {
		// A real PKCS#12 that will not open under the empty password is one this
		// cannot rewrite; the caller reports it as unstrippable, which fails the
		// build because the sweep only reaches a file that holds the certificate.
		logf("%s is a PKCS#12 keystore this cannot decode: %v", path, err)
		return false, nil
	}

	kept := slices.DeleteFunc(certs, func(cert *x509.Certificate) bool {
		return holdsAnyDER(cert.Raw, ders)
	})
	if len(kept) == len(certs) {
		// The DER a scan found is in the file's own bytes but not as a decoded
		// trusted certificate: it is somewhere this rewrite does not reach, so
		// removing nothing and leaving the caller to report it is right.
		return false, nil
	}

	rewritten, err := encodePKCS12(kept)
	if err != nil {
		return false, err
	}
	if _, err := f.WriteAt(rewritten, 0); err != nil {
		return false, err
	}
	return true, f.Truncate(int64(len(rewritten)))
}
