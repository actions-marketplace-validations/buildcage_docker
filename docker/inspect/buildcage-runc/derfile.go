package main

// Mono's cert-sync, registered as an update-ca-certificates hook by
// ca-certificates-mono, splits the system trust into one bare DER per certificate
// under /usr/share/.mono/certs/Trust. The injected CA lands there in a file of
// its own that no PEM removal reaches and the PKCS#12 decode cannot open. Such a
// file holds nothing but the CA, so emptying it takes the CA out and the sweep
// drops the emptied file.

import "crypto/x509"

// holdsOnlyInjectedCert reports whether content is exactly one DER certificate
// whose bytes are the injected CA. x509.ParseCertificate rejects trailing bytes,
// so a file carrying anything past the certificate is left for another decoder.
func holdsOnlyInjectedCert(content []byte, ders [][]byte) bool {
	cert, err := x509.ParseCertificate(content)
	if err != nil {
		return false
	}
	return holdsAnyDER(cert.Raw, ders)
}
