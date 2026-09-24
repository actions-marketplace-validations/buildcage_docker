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
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
	"slices"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// Most key-derivation iterations a PKCS#12 may name before it is left unread.
// go-pkcs12 runs whatever count the file names, at about 0.3 µs an iteration,
// so a 1 KB file naming 2^40 holds a decode for days. Real encoders stay well
// under this: OpenSSL writes 2048, the JDK 10,000 to 100,000.
const maxPKCS12Iterations = 1_000_000

// How deep iterationsWithin descends. go-pkcs12 reads no count deeper than
// PBKDF2's parameters inside a shrouded key bag, 16 levels down.
const maxPKCS12Depth = 24

var errTooManyIterations = errors.New("the PKCS#12 names more key-derivation iterations than this runs")

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
	if !iterationsWithin(content, 0) {
		return nil, errTooManyIterations
	}
	return pkcs12.DecodeTrustStore(content, "")
}

// iterationsWithin reports whether every iteration count der names in the clear
// is at most maxPKCS12Iterations.
//
// The counts are found by shape rather than by walking the PFX structure:
// MacData, the PBE parameters and PBKDF2's all put the count right after the
// salt, an INTEGER following an OCTET STRING. Octet strings are read into,
// since the authenticated safe and its bags sit inside them; one that does not
// parse is ciphertext, and no count inside it is reached before decrypting it.
func iterationsWithin(der []byte, depth int) bool {
	if depth > maxPKCS12Depth {
		return true
	}
	afterSalt := false
	for len(der) > 0 {
		var v asn1.RawValue
		rest, err := asn1.Unmarshal(der, &v)
		if err != nil {
			return true
		}
		der = rest
		universal := v.Class == asn1.ClassUniversal
		switch {
		case universal && v.Tag == asn1.TagInteger && afterSalt:
			var count *big.Int
			if _, err := asn1.Unmarshal(v.FullBytes, &count); err != nil || count.Cmp(big.NewInt(maxPKCS12Iterations)) > 0 {
				return false
			}
		case v.IsCompound || universal && v.Tag == asn1.TagOctetString:
			if !iterationsWithin(v.Bytes, depth+1) {
				return false
			}
		}
		afterSalt = universal && v.Tag == asn1.TagOctetString && !v.IsCompound
	}
	return true
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
	if !iterationsWithin(content, 0) {
		logf("left a PKCS#12 unread: %v", errTooManyIterations)
		return false, nil
	}
	key := sealedResultKey(content, needles)
	if found, ok := sealedResults[key]; ok {
		return found, nil
	}
	found := slices.ContainsFunc(sealedKeystorePasswords, func(password string) bool {
		return slices.ContainsFunc(pkcs12Certificates(content, password), func(cert *x509.Certificate) bool {
			return holdsAnyDER(cert.Raw, needles)
		})
	})
	sealedResults[key] = found
	return found, nil
}

// sealedResults remembers what sealedPKCS12Holds said of each keystore. A file
// is checked several times (found, rechecked before the strip, again after it,
// and in the read-back), and once sealedDecodeBudget runs out a fresh decode
// would say false: a copy found but not removable would then pass as removed.
var sealedResults = map[[sha256.Size]byte]bool{}

func sealedResultKey(content []byte, needles [][]byte) [sha256.Size]byte {
	h := sha256.New()
	h.Write(content)
	for _, needle := range needles {
		h.Write(needle)
	}
	return [sha256.Size]byte(h.Sum(nil))
}

// How long the decodes pkcs12Certificates runs may take in total, across the
// whole step. A key bag's count can sit inside a bag encrypted under the same
// password, which iterationsWithin cannot read, so the decodes are timed too.
// Past it, encrypted keystores pass unread, the same as one under a password
// not in sealedKeystorePasswords.
var sealedDecodeBudget = 30 * time.Second

// pkcs12Certificates decodes content as sealedDecode does, within what is left
// of sealedDecodeBudget. A decode that runs out of it is left running: nothing
// stops go-pkcs12 partway, and the process exits once the step is swept.
func pkcs12Certificates(content []byte, password string) []*x509.Certificate {
	if sealedDecodeBudget <= 0 {
		return nil
	}
	started := time.Now()
	done := make(chan []*x509.Certificate, 1)
	go func() { done <- sealedDecode(content, password) }()
	timeout := time.NewTimer(sealedDecodeBudget)
	defer timeout.Stop()
	select {
	case certs := <-done:
		sealedDecodeBudget -= time.Since(started)
		return certs
	case <-timeout.C:
		sealedDecodeBudget = 0
		logf("decoding encrypted PKCS#12 keystores ran out of time; the rest of this step's pass unread")
		return nil
	}
}

// sealedDecode decodes content as a trust store or as a key with its chain, the
// two shapes go-pkcs12 supports. Nil if neither opens. It is a var so a test can
// stand in a decode that never returns.
var sealedDecode = func(content []byte, password string) []*x509.Certificate {
	if certs, err := pkcs12.DecodeTrustStore(content, password); err == nil {
		return certs
	}
	if _, cert, chain, err := pkcs12.DecodeChain(content, password); err == nil {
		return append(chain, cert)
	}
	return nil
}
