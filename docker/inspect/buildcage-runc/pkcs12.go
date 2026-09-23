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
// back Passwordless, whose bags are unencrypted and carry no MAC, the one shape
// the JVM's default loader trusts as a cacerts: the Modern encoders encrypt the
// bags with PBES2, which that loader does not decrypt. A cacerts keytool or a
// Modern encoder wrote seals a MAC under its own password, so the empty-password
// decode will not open it and it stays fail-closed (errUnstrippableCA) rather
// than being passed silently. removeFromBinaryStore reads the file and
// dispatches on its magic.

import (
	"crypto/x509"
	"io"
	"slices"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// looksLikePKCS12 reports whether content opens the way a PKCS#12 keystore
// does: the DER SEQUENCE tag 0x30 followed by a long-form length, the 0x80 bit
// set. Keystores are far larger than the 127 bytes a short-form length reaches,
// so they always use long form; how many length bytes follow varies with size
// (0x82 for two, 0x83 for three, which a JDK cacerts is large enough to need).
// This only steers which decoder is tried; the decode confirms the bytes really
// are a trust store.
func looksLikePKCS12(content []byte) bool {
	return len(content) >= 2 && content[0] == 0x30 && content[1]&0x80 != 0
}

// decodePKCS12 reads the trusted certificates out of a JDK trust store under
// the empty password. See the file comment for why that is the right password.
func decodePKCS12(content []byte) ([]*x509.Certificate, error) {
	return pkcs12.DecodeTrustStore(content, "")
}

// encodePKCS12 writes certs back as a passwordless trust store (see the file
// comment). It is a var so a test can make the encode fail, which valid
// certificates under the empty password otherwise never do.
var encodePKCS12 = func(certs []*x509.Certificate) ([]byte, error) {
	return pkcs12.Passwordless.EncodeTrustStore(certs, "")
}

// pkcs12Without returns a passwordless PKCS#12 trust store holding everything in
// content but the certificate, and reports whether it removed anything. content
// is already known to begin with the PKCS#12 magic.
//
// A store the empty password will not open, or one holding the DER among its
// bytes but not as a decoded trusted certificate, is one this cannot rewrite: it
// returns (nil, false, nil) and leaves the caller to report it. Removing the
// last certificate is fine: the emptied store re-encodes and decodes cleanly,
// carrying no DER.
// pkcs12With returns a passwordless PKCS#12 trust store holding everything in
// content plus a trusted certificate for each der. content is already known to
// begin with the PKCS#12 magic. A store the empty password will not open is one
// this cannot rewrite, so injection is skipped for it and the step's JVM is left
// not trusting the CA.
func pkcs12With(content []byte, ders [][]byte) ([]byte, error) {
	certs, err := decodePKCS12(content)
	if err != nil {
		return nil, err
	}
	for _, der := range ders {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return encodePKCS12(certs)
}

func pkcs12Without(content []byte, ders [][]byte) ([]byte, bool, error) {
	certs, err := decodePKCS12(content)
	if err != nil {
		logf("a PKCS#12 keystore this cannot decode under the empty password: %v", err)
		return nil, false, nil
	}
	// Captured before the delete: slices.DeleteFunc rewrites certs' backing array
	// in place and returns a shorter slice, leaving certs' own length unchanged,
	// so comparing kept against it is what says a copy was found.
	before := len(certs)
	kept := slices.DeleteFunc(certs, func(cert *x509.Certificate) bool {
		return holdsAnyDER(cert.Raw, ders)
	})
	if len(kept) == before {
		return nil, false, nil
	}
	out, err := encodePKCS12(kept)
	if err != nil {
		return nil, false, err
	}
	return out, true, nil
}

// Passwords tried on an encrypted PKCS#12: none, and the JDK default a copy of
// cacerts usually keeps. Others pass unread: dependencies ship encrypted test
// keystores (the Azure SDK for Go does), and failing on those would fail
// builds that never touched the CA.
var sealedKeystorePasswords = []string{"", keystorePassword}

// sealedPKCS12Holds reports whether f is a PKCS#12 that opens under one of
// sealedKeystorePasswords and holds a certificate carrying one of needles.
func sealedPKCS12Holds(f io.ReaderAt, size int64, needles [][]byte) (bool, error) {
	if size < 2 || size > maxKeystoreBytes {
		return false, nil
	}
	// Nearly every file is not a keystore, so the magic is checked before
	// reading the whole file.
	head := make([]byte, 2)
	if _, err := f.ReadAt(head, 0); err != nil {
		return false, err
	}
	if !looksLikePKCS12(head) {
		return false, nil
	}
	content := make([]byte, size)
	if _, err := f.ReadAt(content, 0); err != nil && err != io.EOF {
		return false, err
	}
	for _, password := range sealedKeystorePasswords {
		for _, cert := range pkcs12Certificates(content, password) {
			if holdsAnyDER(cert.Raw, needles) {
				return true, nil
			}
		}
	}
	return false, nil
}

// pkcs12Certificates decodes content as a trust store or as a key with its
// chain, the two shapes go-pkcs12 supports. Nil if neither opens.
func pkcs12Certificates(content []byte, password string) []*x509.Certificate {
	if certs, err := pkcs12.DecodeTrustStore(content, password); err == nil {
		return certs
	}
	if _, cert, chain, err := pkcs12.DecodeChain(content, password); err == nil {
		return append(chain, cert)
	}
	return nil
}
