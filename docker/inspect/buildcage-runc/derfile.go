package main

// Mono's cert-sync writes the system trust as one bare DER per certificate under
// /usr/share/.mono/certs/Trust, and installing ca-certificates-mono registers it
// as an update-ca-certificates hook, so any step that runs that hook copies the
// injected CA there as a file of its own. That file holds nothing but the
// certificate: no PEM removal reaches a bare DER, and the PKCS#12 decode cannot
// open one, so before this the sweep could see the copy but not take it out and
// failed the build (errUnstrippableCA). A file that is one certificate and that
// certificate is the injected CA is one the injection produced whole, so emptying
// it takes the CA out, and the sweep drops the emptied file the way it drops any
// other trace.

import "crypto/x509"

// holdsOnlyInjectedCert reports whether content is exactly one DER certificate
// whose bytes are the injected CA. x509.ParseCertificate rejects trailing bytes,
// so a file carrying anything past the certificate is not one of these and is
// left for another decoder to try.
func holdsOnlyInjectedCert(content []byte, ders [][]byte) bool {
	cert, err := x509.ParseCertificate(content)
	if err != nil {
		return false
	}
	return holdsAnyDER(cert.Raw, ders)
}
