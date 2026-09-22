package main

import (
	"bytes"
	"crypto/sha1"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeRootfsKeystore places raw keystore bytes at a container path inside
// rootfs, creating the directories on the way.
func writeRootfsKeystore(t *testing.T, rootfs, containerPath string, content []byte) {
	t.Helper()
	abs := filepath.Join(rootfs, strings.TrimPrefix(containerPath, "/"))
	mustMkdirAll(t, filepath.Dir(abs))
	mustWriteFile(t, abs, string(content))
}

func TestFindJVMKeystoreFromJavaHome(t *testing.T) {
	rootfs := t.TempDir()
	s := &spec{rootfs: rootfs, env: map[string]string{"JAVA_HOME": "/opt/java"}}
	cacerts := filepath.Join(rootfs, "opt/java/lib/security/cacerts")
	mustMkdirAll(t, filepath.Dir(cacerts))
	mustWriteFile(t, cacerts, "x")

	got, ok := findJVMKeystore(s)
	if !ok || got != cacerts {
		t.Fatalf("findJVMKeystore = %q, %v; want %q, true", got, ok, cacerts)
	}
}

// JAVA_HOME unset, a JVM at a known fixed path instead (Debian's symlinked
// cacerts, followed to its real file).
func TestFindJVMKeystoreFromKnownPath(t *testing.T) {
	rootfs := t.TempDir()
	s := &spec{rootfs: rootfs, env: map[string]string{}}
	cacerts := filepath.Join(rootfs, "etc/ssl/certs/java/cacerts")
	mustMkdirAll(t, filepath.Dir(cacerts))
	mustWriteFile(t, cacerts, "x")

	got, ok := findJVMKeystore(s)
	if !ok || got != cacerts {
		t.Fatalf("findJVMKeystore = %q, %v; want %q, true", got, ok, cacerts)
	}
}

// JAVA_HOME names a keystore that is not there, so discovery falls through to
// the known paths and, finding none either, reports no keystore.
func TestFindJVMKeystoreNoneFound(t *testing.T) {
	s := &spec{rootfs: t.TempDir(), env: map[string]string{"JAVA_HOME": "/opt/java"}}
	if got, ok := findJVMKeystore(s); ok {
		t.Fatalf("found a keystore where there is none: %q", got)
	}
}

// A JAVA_HOME cacerts that is a directory, not a file, is not a keystore to
// inject into and is passed over.
func TestFindJVMKeystoreIgnoresANonRegularFile(t *testing.T) {
	rootfs := t.TempDir()
	s := &spec{rootfs: rootfs, env: map[string]string{"JAVA_HOME": "/opt/java"}}
	mustMkdirAll(t, filepath.Join(rootfs, "opt/java/lib/security/cacerts"))
	if _, ok := findJVMKeystore(s); ok {
		t.Fatal("a directory was taken for a keystore")
	}
}

func TestInsertIntoKeystoreJKS(t *testing.T) {
	path := mustWriteKeystore(t, keystore(2, trustedEntry(2, "digicert", otherDER)))
	if err := insertIntoKeystore(path, testCA); err != nil {
		t.Fatalf("insertIntoKeystore: %v", err)
	}
	out, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out, []byte(injectedAlias)) || !bytes.Contains(out, testDER) {
		t.Error("the CA was not inserted into the JKS")
	}
	// Well-formed and sealed: removal reads it back without complaint.
	if _, err := removeFromKeystore(path, [][]byte{testDER}); err != nil {
		t.Fatalf("the injected keystore is not one removal accepts: %v", err)
	}
}

func TestInsertIntoKeystorePKCS12(t *testing.T) {
	root := testCert(t, "digicert")
	ca := testCert(t, "buildcage")
	path := mustWritePKCS12(t, passwordlessStore(t, root))
	if err := insertIntoKeystore(path, certPEM(ca)); err != nil {
		t.Fatalf("insertIntoKeystore: %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	certs, err := decodePKCS12(content)
	if err != nil {
		t.Fatalf("the injected store no longer decodes: %v", err)
	}
	if len(certs) != 2 {
		t.Errorf("the injected store holds %d certificates, want 2", len(certs))
	}
}

func TestInsertIntoKeystoreNeedsACertificate(t *testing.T) {
	path := mustWriteKeystore(t, keystore(2, trustedEntry(2, "digicert", otherDER)))
	if err := insertIntoKeystore(path, []byte("no PEM certificate here")); !errors.Is(err, errNotACertificate) {
		t.Fatalf("got %v, want errNotACertificate", err)
	}
}

func TestInsertIntoKeystoreRejectsNonKeystore(t *testing.T) {
	path := mustWriteKeystore(t, []byte("not a keystore, just some bytes"))
	if err := insertIntoKeystore(path, testCA); !errors.Is(err, errNotAKeystore) {
		t.Fatalf("got %v, want errNotAKeystore", err)
	}
}

func TestInsertIntoKeystoreRejectsTooSmall(t *testing.T) {
	path := mustWriteKeystore(t, []byte{0xfe, 0xed})
	if err := insertIntoKeystore(path, testCA); !errors.Is(err, errNotAKeystore) {
		t.Fatalf("got %v, want errNotAKeystore", err)
	}
}

func TestInsertIntoKeystoreRejectsTooLarge(t *testing.T) {
	t.Cleanup(func(prev int64) func() { return func() { maxKeystoreBytes = prev } }(maxKeystoreBytes))
	maxKeystoreBytes = 4
	path := mustWriteKeystore(t, keystore(2, trustedEntry(2, "digicert", otherDER)))
	if err := insertIntoKeystore(path, testCA); !errors.Is(err, errNotAKeystore) {
		t.Fatalf("got %v, want errNotAKeystore", err)
	}
}

// A PKCS#12 the empty password will not open reaches injection as a keystore
// but cannot be rewritten; the error is reported for the caller to skip on.
func TestInsertIntoKeystoreReportsADecodeFailure(t *testing.T) {
	ca := testCert(t, "buildcage")
	path := mustWritePKCS12(t, encryptedStore(t, ca))
	if err := insertIntoKeystore(path, certPEM(ca)); err == nil {
		t.Fatal("want the decode failure to be reported")
	}
}

func TestInsertIntoKeystoreReportsAStatFailure(t *testing.T) {
	path := mustWriteKeystore(t, keystore(2, trustedEntry(2, "digicert", otherDER)))
	useBrokenBundleFile(t, &brokenFile{failStat: true})
	if err := insertIntoKeystore(path, testCA); !errors.Is(err, errBrokenFile) {
		t.Fatalf("got %v, want the stat failure", err)
	}
}

func TestInsertIntoKeystoreReportsAReadFailure(t *testing.T) {
	path := mustWriteKeystore(t, keystore(2, trustedEntry(2, "digicert", otherDER)))
	useBrokenBundleFile(t, &brokenFile{failReadAt: 1})
	if err := insertIntoKeystore(path, testCA); !errors.Is(err, errBrokenFile) {
		t.Fatalf("got %v, want the read failure", err)
	}
}

func TestInsertIntoKeystoreReportsAWriteFailure(t *testing.T) {
	path := mustWriteKeystore(t, keystore(2, trustedEntry(2, "digicert", otherDER)))
	useBrokenBundleFile(t, &brokenFile{failWriteAt: 1})
	if err := insertIntoKeystore(path, testCA); !errors.Is(err, errBrokenFile) {
		t.Fatalf("got %v, want the write failure", err)
	}
}

func TestInsertIntoKeystoreRefusesAPathThatIsNotThere(t *testing.T) {
	if err := insertIntoKeystore(filepath.Join(t.TempDir(), "gone"), testCA); err == nil {
		t.Fatal("expected a missing keystore to be reported")
	}
}

// inject discovers the base image's JVM keystore and adds the CA to the scratch
// mirror bound over it, never the real file, the same as the system store.
func TestInjectAddsCAToTheJVMKeystore(t *testing.T) {
	useFakeRsync(t)
	bundle, rootfs := newBundle(t, []string{"JAVA_HOME=/opt/java"})
	writeRootfsKeystore(t, rootfs, "/opt/java/lib/security/cacerts",
		keystore(2, trustedEntry(2, "digicert", otherDER)))

	restore, err := inject(bundle, testCA)
	if err != nil {
		t.Fatal(err)
	}
	defer restore.finish(true)

	mount := findMount(t, loadMounts(t, bundle), "/opt/java/lib/security")
	scratch, _ := mount["source"].(string)
	mirrored, err := os.ReadFile(filepath.Join(scratch, "cacerts"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(mirrored, []byte(injectedAlias)) || !bytes.Contains(mirrored, testDER) {
		t.Fatal("the CA was not inserted into the mirrored keystore")
	}

	real, err := os.ReadFile(filepath.Join(rootfs, "opt/java/lib/security/cacerts"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(real, []byte(injectedAlias)) {
		t.Fatal("the real keystore was modified before the step touched it")
	}
}

// A step that never touches the keystore leaves the real file alone: finish
// finds the mirror unchanged from its post-injection baseline.
func TestInjectLeavesAnUntouchedKeystoreAlone(t *testing.T) {
	useFakeRsync(t)
	bundle, rootfs := newBundle(t, []string{"JAVA_HOME=/opt/java"})
	original := keystore(2, trustedEntry(2, "digicert", otherDER))
	writeRootfsKeystore(t, rootfs, "/opt/java/lib/security/cacerts", original)

	restore, err := inject(bundle, testCA)
	if err != nil {
		t.Fatal(err)
	}
	if err := restore.finish(true); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(filepath.Join(rootfs, "opt/java/lib/security/cacerts"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatal("the real keystore was written to even though nothing changed")
	}
}

// A step that changes the keystore gets its change written back with the proxy
// CA taken out and its own additions kept.
func TestInjectWritesBackWhenTheStepChangesTheKeystore(t *testing.T) {
	useFakeRsync(t)
	bundle, rootfs := newBundle(t, []string{"JAVA_HOME=/opt/java"})
	writeRootfsKeystore(t, rootfs, "/opt/java/lib/security/cacerts",
		keystore(2, trustedEntry(2, "digicert", otherDER)))

	restore, err := inject(bundle, testCA)
	if err != nil {
		t.Fatal(err)
	}

	mount := findMount(t, loadMounts(t, bundle), "/opt/java/lib/security")
	scratch, _ := mount["source"].(string)
	// The step adds its own root to the already CA-injected keystore.
	stepStore := keystore(2,
		trustedEntry(2, "digicert", otherDER),
		trustedEntry(2, "steproot", []byte("STEP-ROOT")),
		trustedEntry(2, injectedAlias, testDER))
	mustWriteFile(t, filepath.Join(scratch, "cacerts"), string(stepStore))

	if err := restore.finish(true); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(filepath.Join(rootfs, "opt/java/lib/security/cacerts"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(got, testDER) {
		t.Fatal("the proxy CA was left in the written-back keystore")
	}
	if !bytes.Contains(got, []byte("STEP-ROOT")) {
		t.Fatal("the step's own root was lost in the write-back")
	}
}

// A keystore that cannot be injected into (here a PKCS#12 the empty password
// will not open) is bound but left un-injected, so the step's JVM simply does
// not trust the CA rather than the build failing.
func TestInjectSkipsAnUninjectableKeystore(t *testing.T) {
	useFakeRsync(t)
	bundle, rootfs := newBundle(t, []string{"JAVA_HOME=/opt/java"})
	writeRootfsKeystore(t, rootfs, "/opt/java/lib/security/cacerts",
		encryptedStore(t, testCert(t, "root")))

	restore, err := inject(bundle, testCA)
	if err != nil {
		t.Fatal(err)
	}
	defer restore.finish(true)

	mount := findMount(t, loadMounts(t, bundle), "/opt/java/lib/security")
	scratch, _ := mount["source"].(string)
	mirrored, err := os.ReadFile(filepath.Join(scratch, "cacerts"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(mirrored, testDER) {
		t.Fatal("something was injected into a keystore that cannot take it")
	}
}

// A JDK 8 keeps cacerts under jre/lib/security, its JAVA_HOME being the JDK root.
func TestFindJVMKeystoreFromJavaHomeJre(t *testing.T) {
	rootfs := t.TempDir()
	s := &spec{rootfs: rootfs, env: map[string]string{"JAVA_HOME": "/opt/jdk8"}}
	cacerts := filepath.Join(rootfs, "opt/jdk8/jre/lib/security/cacerts")
	mustMkdirAll(t, filepath.Dir(cacerts))
	mustWriteFile(t, cacerts, "x")

	got, ok := findJVMKeystore(s)
	if !ok || got != cacerts {
		t.Fatalf("findJVMKeystore = %q, %v; want %q, true", got, ok, cacerts)
	}
}

// Every certificate in the CA is inserted, not only the first, so a multi-cert
// CA leaves the JVM trusting all of it the way the PEM stores do.
func TestKeystoreWithInsertsEveryCert(t *testing.T) {
	out, err := keystoreWith(keystore(2, trustedEntry(2, "digicert", otherDER)),
		[][]byte{testDER, []byte("SECOND-CA")})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out, testDER) || !bytes.Contains(out, []byte("SECOND-CA")) {
		t.Error("not every certificate was inserted")
	}
	_, entries, err := parseKeystore(out[:len(out)-sha1.Size])
	if err != nil {
		t.Fatalf("the result does not parse: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want the original plus two", len(entries))
	}
}

func TestPKCS12WithInsertsEveryCert(t *testing.T) {
	root := testCert(t, "digicert")
	ca1 := testCert(t, "buildcage-1")
	ca2 := testCert(t, "buildcage-2")
	out, err := pkcs12With(passwordlessStore(t, root), [][]byte{ca1.Raw, ca2.Raw})
	if err != nil {
		t.Fatal(err)
	}
	certs, err := decodePKCS12(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 3 {
		t.Fatalf("got %d certificates, want the original plus two", len(certs))
	}
}

// A Debian JDK's cacerts is a symlink into the CA store directory, which the
// store's own bind already mirrors; the CA goes into that mirror's copy of the
// keystore rather than a second bind the store mount would shadow.
func TestInjectCoversAKeystoreInsideTheStoreDir(t *testing.T) {
	useFakeRsync(t)
	bundle, rootfs := newBundle(t, []string{"JAVA_HOME=/opt/java"})
	writeRootfsKeystore(t, rootfs, "/etc/ssl/certs/java/cacerts",
		keystore(2, trustedEntry(2, "digicert", otherDER)))
	mustMkdirAll(t, filepath.Join(rootfs, "opt/java/lib/security"))
	mustSymlink(t, "/etc/ssl/certs/java/cacerts",
		filepath.Join(rootfs, "opt/java/lib/security/cacerts"))

	restore, err := inject(bundle, testCA)
	if err != nil {
		t.Fatal(err)
	}
	defer restore.finish(true)

	// One bind covers the store directory; the keystore is not bound separately.
	for _, m := range loadMounts(t, bundle) {
		if m["destination"] == "/etc/ssl/certs/java" {
			t.Fatal("the keystore was bound separately, which the store mount shadows")
		}
	}

	mount := findMount(t, loadMounts(t, bundle), "/etc/ssl/certs")
	scratch, _ := mount["source"].(string)
	mirrored, err := os.ReadFile(filepath.Join(scratch, "java", "cacerts"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(mirrored, []byte(injectedAlias)) || !bytes.Contains(mirrored, testDER) {
		t.Fatal("the CA was not inserted into the keystore inside the store mirror")
	}

	real, err := os.ReadFile(filepath.Join(rootfs, "etc/ssl/certs/java/cacerts"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(real, []byte(injectedAlias)) {
		t.Fatal("the real keystore was modified before the step touched it")
	}
}
