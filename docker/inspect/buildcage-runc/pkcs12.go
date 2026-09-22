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
//
// A keytool- or Modern-written PKCS#12 seals a MAC keyed on its own password, so
// the empty-password decode below will not open it. That is intentional: this
// rewrites the passwordless shape the wrapper's own injection produces, and any
// other keystore that still holds the certificate stays fail-closed
// (errUnstrippableCA) rather than being passed silently. removeFromKeystore is
// where the file is read and dispatched on its magic.

import (
	"crypto/x509"
	"slices"

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

// pkcs12Without returns a passwordless PKCS#12 trust store holding everything in
// content but the certificate, and reports whether it removed anything. content
// is already known to begin with the PKCS#12 magic.
//
// A store that will not open under the empty password, or that holds the DER
// among its bytes but not as a decoded trusted certificate, is one this cannot
// rewrite: it returns (nil, false, nil) so removeFromKeystore leaves the file
// alone. Reached only when the certificate is already known to be in the file,
// that leaves the caller to report it, which fails the build rather than passing
// a copy it could not take out. Removing the last certificate is fine: the
// resulting empty store re-encodes and decodes cleanly, carrying no DER.
func pkcs12Without(content []byte, ders [][]byte) ([]byte, bool, error) {
	certs, err := decodePKCS12(content)
	if err != nil {
		logf("a PKCS#12 keystore this cannot decode under the empty password: %v", err)
		return nil, false, nil
	}
	// Captured before the delete: slices.DeleteFunc rewrites certs' own backing
	// array and shortens the slice it returns, leaving certs' length as it was.
	// Comparing kept against that original length is what says a copy was found.
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
