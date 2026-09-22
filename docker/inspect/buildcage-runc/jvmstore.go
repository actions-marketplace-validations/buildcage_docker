package main

// A JVM already in the base image (eclipse-temurin, amazoncorretto, gradle,
// maven, ...) reads its trusted roots from its own keystore at
// $JAVA_HOME/lib/security/cacerts and consults neither the system CA store nor
// the CA-trust environment variables the wrapper otherwise sets. So `mvn`,
// `gradle` and `java` do not trust the proxy's CA the way the rest of a step's
// tooling does. This adds the CA to that keystore for the step's duration, the
// same mirror-and-bind way the system store is handled: the injection lands in
// the scratch mirror, never the real file, and the layer sweep is what takes it
// back out of a keystore a step went on to change.
//
// A step that installs a JRE part-way through is a different case, already
// covered by the anchors ca-certificates-java imports; this is for the JVM that
// was there from the start.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// errNotAKeystore means the file discovery pointed at does not begin with
// either keystore magic, so injection has nothing it knows how to write.
var errNotAKeystore = errors.New("not a JKS or PKCS#12 keystore")

// The alias and creation time the injected trusted-certificate entry carries in
// a JKS. The time is fixed so the entry is byte-for-byte the same every build,
// which keeps the gatekeeper comparing like with like; the alias only has to not
// collide with one the keystore already uses.
const (
	injectedAlias        = "buildcage-proxy-ca"
	injectedCreationTime = 1700000000000
)

// Keystores tried when JAVA_HOME is unset. JAVA_HOME covers the Java base
// images this is aimed at; this catches a JVM installed at a fixed location
// without it. /etc/ssl/certs/java/cacerts is Debian's ca-certificates-java
// output, a symlink resolveInRoot follows to the real file.
var knownJVMKeystores = []string{
	"/etc/ssl/certs/java/cacerts",
}

// findJVMKeystore locates the existing JVM keystore inside the rootfs, from
// JAVA_HOME first and then the known fixed paths. It returns the resolved host
// path of the keystore file, or ok=false when the image carries no JVM keystore
// this knows to look for.
func findJVMKeystore(s *spec) (string, bool) {
	var candidates []string
	if home := s.env["JAVA_HOME"]; home != "" {
		candidates = append(candidates, filepath.Join(home, "lib", "security", "cacerts"))
	}
	candidates = append(candidates, knownJVMKeystores...)

	for _, candidate := range candidates {
		resolved, err := resolveInRoot(s.rootfs, candidate)
		if err != nil {
			continue
		}
		if info, err := os.Stat(resolved); err == nil && info.Mode().IsRegular() {
			return resolved, true
		}
	}
	return "", false
}

// insertIntoKeystore adds a trusted-certificate entry for the CA to the keystore
// at path, rewriting it in place. Like removeFromKeystore it reads the file once
// and dispatches on its magic. An error leaves the keystore untouched for the
// caller to report; the step's JVM then simply does not trust the CA, the
// behaviour it had before this existed.
func insertIntoKeystore(path string, ca []byte) error {
	ders := certificateDERs(ca)
	if len(ders) == 0 {
		return errNotACertificate
	}

	f, err := openBundle(path, os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return asNotRegular(path, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	size := info.Size()
	if size < int64(len(keystoreMagic)) || size > maxKeystoreBytes {
		return errNotAKeystore
	}
	content := make([]byte, size)
	if _, err := f.ReadAt(content, 0); err != nil && err != io.EOF {
		return err
	}

	var injected []byte
	switch {
	case bytes.HasPrefix(content, keystoreMagic):
		injected, err = keystoreWith(content, ders[0])
	case looksLikePKCS12(content):
		injected, err = pkcs12With(content, ders[0])
	default:
		return errNotAKeystore
	}
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}

	if _, err := f.WriteAt(injected, 0); err != nil {
		return err
	}
	return f.Truncate(int64(len(injected)))
}
