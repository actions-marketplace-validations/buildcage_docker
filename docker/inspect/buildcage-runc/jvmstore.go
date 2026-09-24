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

// The alias the injected trusted-certificate entry carries in either keystore
// shape, and its creation time in a JKS. The time is fixed so the entry is
// byte-for-byte the same every build, which keeps the gatekeeper comparing like
// with like; the alias only has to not collide with one the keystore already
// uses.
const (
	injectedAlias        = "buildcage-proxy-ca"
	injectedCreationTime = 1700000000000
)

// injectedAliasFor is the alias of the i-th injected certificate. One entry
// keeps the plain alias, so the common single-certificate CA injects the same
// every build; a bundle's later entries take a suffix, since a keystore keeps
// one entry per alias.
func injectedAliasFor(i int) string {
	if i == 0 {
		return injectedAlias
	}
	return fmt.Sprintf("%s-%d", injectedAlias, i)
}

// The keystore file names a JVM's default trust manager reads, in the order it
// prefers them: jssecacerts overrides cacerts entirely when it is present, so
// the CA has to go into whichever exist, not cacerts alone.
var jvmKeystoreNames = []string{"jssecacerts", "cacerts"}

// Security directories tried when JAVA_HOME is unset. JAVA_HOME covers the Java
// base images this is aimed at; these catch a JVM installed at a fixed location
// without it. /etc/ssl/certs/java is Debian's ca-certificates-java output and
// the /etc/pki ones are RHEL's, each a symlink resolveInRoot follows to the
// real file.
var knownJVMKeystoreDirs = []string{
	"/etc/ssl/certs/java",
	"/etc/pki/java",
	"/etc/pki/ca-trust/extracted/java",
}

// findJVMKeystores returns the resolved host paths of every JVM keystore inside
// the rootfs, from JAVA_HOME first and then the known fixed directories, each
// deduplicated by where it resolves so a symlinked one is not injected twice.
func findJVMKeystores(s *spec) []string {
	var dirs []string
	if home := s.env["JAVA_HOME"]; home != "" {
		// lib/security is the layout from JDK 9 on; jre/lib/security is where a
		// JDK 8's JAVA_HOME (the JDK root, with the JRE under jre/) keeps it.
		dirs = append(dirs,
			filepath.Join(home, "lib", "security"),
			filepath.Join(home, "jre", "lib", "security"),
		)
	}
	dirs = append(dirs, knownJVMKeystoreDirs...)

	var keystores []string
	seen := map[string]bool{}
	for _, dir := range dirs {
		for _, name := range jvmKeystoreNames {
			resolved, err := resolveInRoot(s.rootfs, filepath.Join(dir, name))
			if err != nil || seen[resolved] {
				continue
			}
			if info, err := os.Stat(resolved); err == nil && info.Mode().IsRegular() {
				seen[resolved] = true
				keystores = append(keystores, resolved)
			}
		}
	}
	return keystores
}

// insertIntoKeystore adds a trusted-certificate entry for the CA to the keystore
// at path, rewriting it in place. Like removeFromBinaryStore it reads the file
// once and dispatches on its magic. On success it returns the keystore's
// pre-injection bytes for the caller to restore later. An error leaves the
// keystore untouched for the caller to report, so the step's JVM does not trust
// the CA.
func insertIntoKeystore(path string, ca []byte) ([]byte, error) {
	ders := certificateDERs(ca)
	if len(ders) == 0 {
		return nil, errNotACertificate
	}

	f, err := openBundle(path, os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, asNotRegular(path, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := info.Size()
	if size < int64(len(keystoreMagic)) || size > maxKeystoreBytes {
		return nil, errNotAKeystore
	}
	content := make([]byte, size)
	if _, err := f.ReadAt(content, 0); err != nil && err != io.EOF {
		return nil, err
	}

	// Every certificate in the CA file, as appendCA adds for the PEM stores, so
	// a multi-certificate CA is trusted whole rather than only its first.
	var injected []byte
	switch {
	case bytes.HasPrefix(content, keystoreMagic):
		injected, err = keystoreWith(content, ders)
	case looksLikePKCS12(content):
		injected, err = pkcs12With(content, ders)
	default:
		return nil, errNotAKeystore
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}

	if _, err := f.WriteAt(injected, 0); err != nil {
		return nil, err
	}
	// Returns content alongside a Truncate error; the caller ignores it there.
	return content, f.Truncate(int64(len(injected)))
}
