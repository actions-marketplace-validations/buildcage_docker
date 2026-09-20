package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// What the removal looks for: the certificate's own PEM block. The certificate
// is generated per build, so every copy of it in the bundle is one this wrapper
// put there, however the step rewrote the bundle in between and whatever text
// it left around it.
var (
	beginCertificate = []byte("-----BEGIN CERTIFICATE-----")
	endCertificate   = []byte("-----END CERTIFICATE-----")
)

// How much of a bundle removeCA holds at once. The store directory is a bind
// mount of the scratch mirror while the step runs, so the file is whatever
// size the step left it at, not what the image shipped.
const scanChunk = 64 << 10

// Longest PEM block removeCA compares in one piece. A certificate is a few KB,
// so anything past this is something else the step left between the two lines
// and is skipped rather than read into memory.
const maxCertificateBytes = 64 << 10

// Same candidate order as buildkit's executor.InjectProxyCA.
var systemCertFiles = []string{
	"/etc/ssl/certs/ca-certificates.crt",
	"/etc/pki/tls/certs/ca-bundle.crt",
	"/etc/ssl/ca-bundle.pem",
	"/etc/pki/tls/cacert.pem",
	"/etc/ssl/cert.pem",
}

var (
	errEscapesRoot     = errors.New("path escapes the rootfs")
	errTooManySymlinks = errors.New("too many symlinks")
)

// errNotRegular means appendCA/removeCA found something other than a plain
// file at the target. The wrapper runs unsandboxed on the host, so opening
// whatever a step swapped the path for (a symlink, a FIFO) would follow
// attacker-controlled input outside the directory it's meant to stay in.
var errNotRegular = errors.New("not a regular file")

// errNotACertificate means what appendCA was handed holds no PEM certificate.
// Nothing is appended that removeCA could not take back out, since what it
// matches on is the certificate itself.
var errNotACertificate = errors.New("not a certificate")

// resolveInRoot resolves path as the container would see it, so a symlink
// cannot be used to reach outside.
//
// The wrapper runs as root on the host while the rootfs comes from an image
// the build chose, so a link placed at one of the paths below would otherwise
// direct an append onto a host file. Absolute links are therefore followed
// from the rootfs rather than from the host's own root, and the result is
// checked to be inside it either way.
func resolveInRoot(rootfs, path string) (string, error) {
	rootfs, err := filepath.Abs(rootfs)
	// Untested by design: Abs only fails when Getwd does, which needs the
	// process's own working directory to have been removed.
	//coverage:ignore start
	if err != nil {
		return "", err
	}
	//coverage:ignore stop
	current := rootfs
	remaining := strings.Split(strings.TrimPrefix(filepath.Clean(path), "/"), "/")

	for hops := 0; len(remaining) > 0; {
		name := remaining[0]
		remaining = remaining[1:]
		if name == "" || name == "." {
			continue
		}
		next := filepath.Join(current, name)
		if !withinRoot(rootfs, next) {
			// ".." climbing above the rootfs lands here.
			return "", errEscapesRoot
		}

		info, err := os.Lstat(next)
		if err != nil {
			if os.IsNotExist(err) && len(remaining) == 0 {
				// The final component may legitimately not exist yet.
				return next, nil
			}
			return "", err
		}
		if info.Mode()&os.ModeSymlink == 0 {
			current = next
			continue
		}

		hops++
		if hops > 32 {
			return "", errTooManySymlinks
		}
		target, err := os.Readlink(next)
		// Untested by design: Lstat has already said this is a symlink, so getting
		// here means the step swapped it in between. Reading it back is what the
		// check is for, and failing to is the same refusal.
		//coverage:ignore start
		if err != nil {
			return "", err
		}
		//coverage:ignore stop
		if filepath.IsAbs(target) {
			// Absolute inside the container means absolute inside the rootfs.
			current = rootfs
		}
		remaining = append(strings.Split(strings.TrimPrefix(filepath.Clean(target), "/"), "/"), remaining...)
	}
	// Untested by design: current is only ever assigned a path the loop has
	// already put through withinRoot, or the rootfs itself. Kept so the
	// confinement is a property of this function rather than of its loop.
	//coverage:ignore start
	if !withinRoot(rootfs, current) {
		return "", errEscapesRoot
	}
	//coverage:ignore stop
	return current, nil
}

func withinRoot(rootfs, path string) bool {
	return path == rootfs || strings.HasPrefix(path, rootfs+string(os.PathSeparator))
}

// asNotRegular folds the open() failures O_NOFOLLOW/O_NONBLOCK produce for a
// symlink or an unread FIFO into errNotRegular, so callers don't need to
// distinguish rejection at open() from rejection after Stat.
func asNotRegular(path string, err error) error {
	if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.ENXIO) {
		return fmt.Errorf("%s: %w", path, errNotRegular)
	}
	return err
}

// bundleFile is the part of *os.File that adding and stripping the CA goes
// through. It is an interface so a test can stand in for it and fail one
// read or write partway, which no fixture on a real filesystem can arrange.
type bundleFile interface {
	io.ReaderAt
	io.WriterAt
	Stat() (fs.FileInfo, error)
	Truncate(size int64) error
	WriteString(s string) (int, error)
	Close() error
}

// openBundle is a var for the same reason.
var openBundle = func(path string, flag int, perm os.FileMode) (bundleFile, error) {
	f, err := os.OpenFile(path, flag, perm)
	if err != nil {
		// Returning f here would hand back a non-nil interface holding a nil
		// *os.File, which every caller's err check would then walk straight past.
		return nil, err
	}
	return f, nil
}

// appendCA adds the certificate to path, creating it when missing.
//
// O_NOFOLLOW/O_NONBLOCK keep the open from following a symlink or blocking on
// a FIFO the step may have left at path since injection.
func appendCA(path string, ca []byte) error {
	if len(certificateBodies(ca)) == 0 {
		return fmt.Errorf("%s: %w", path, errNotACertificate)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := openBundle(path, os.O_CREATE|os.O_RDWR|os.O_APPEND|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o644)
	if err != nil {
		return asNotRegular(path, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s: %w", path, errNotRegular)
	}
	// A bundle that does not end in one needs a line break first, or the
	// opening line lands on the end of the last one and no reader sees a
	// certificate there. Removal takes back the line break that closes the
	// block rather than this one, so a bundle that shipped without a final
	// newline gains one; it can only reach a layer a step was already writing
	// to, since an untouched mirror is discarded rather than written back.
	if info.Size() > 0 {
		nl, err := isNewlineAt(f, info.Size()-1)
		if err != nil {
			return err
		}
		if !nl {
			if _, err := f.WriteString("\n"); err != nil {
				return err
			}
		}
	}
	_, err = f.WriteString(strings.TrimRight(string(ca), "\n") + "\n")
	return err
}

// strippedBody is a PEM body with every space and line break taken out, so the
// same certificate matches however the tool that last wrote it wrapped the
// base64.
func strippedBody(body []byte) string {
	return string(bytes.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, body))
}

// certificateBodies indexes every certificate in pem by its stripped body.
func certificateBodies(pem []byte) map[string]bool {
	bodies := map[string]bool{}
	for rest := pem; ; {
		begin := bytes.Index(rest, beginCertificate)
		if begin == -1 {
			return bodies
		}
		rest = rest[begin+len(beginCertificate):]
		end := bytes.Index(rest, endCertificate)
		if end == -1 {
			return bodies
		}
		bodies[strippedBody(rest[:end])] = true
		rest = rest[end+len(endCertificate):]
	}
}

// span is a half-open byte range of the bundle, one certificate to cut out.
type span struct{ start, end int64 }

// removeCA deletes every copy of the certificate, leaving anything else in
// place.
//
// Returns without error when there is none, since the step may have rewritten
// the file itself. The find and the strip share one handle, opened the same
// guarded way as appendCA, so they can't land on different files.
func removeCA(path string, ca []byte) error {
	bodies := certificateBodies(ca)
	if len(bodies) == 0 {
		return nil
	}

	f, err := openBundle(path, os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return asNotRegular(path, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s: %w", path, errNotRegular)
	}

	size := info.Size()
	cuts, err := findCertificates(f, bodies, size)
	if err != nil || len(cuts) == 0 {
		return err
	}
	kept, err := closeGaps(f, cuts, size)
	if err != nil {
		return err
	}
	return f.Truncate(kept)
}

// findCertificates returns, in order, the range each copy of the certificate
// occupies, including the line break that closes it.
func findCertificates(f bundleFile, bodies map[string]bool, size int64) ([]span, error) {
	var cuts []span
	for off := int64(0); off < size; {
		begin, err := findInFile(f, beginCertificate, off, size)
		if err != nil {
			return nil, err
		}
		if begin == -1 {
			return cuts, nil
		}
		end, err := findInFile(f, endCertificate, begin, size)
		if err != nil {
			return nil, err
		}
		// A block the step truncated mid-certificate has no end to cut to.
		if end == -1 {
			return cuts, nil
		}
		end += int64(len(endCertificate))
		// A candidate that is not the certificate resumes after its opening
		// line rather than after the closing one it was paired with: an
		// opening line the step left without an end of its own would
		// otherwise pair with the next certificate's, and carry that
		// certificate past the scan with it.
		off = begin + int64(len(beginCertificate))

		if end-begin > maxCertificateBytes {
			continue
		}
		block := make([]byte, end-begin)
		if _, err := f.ReadAt(block, begin); err != nil && err != io.EOF {
			return nil, err
		}
		body := block[len(beginCertificate) : len(block)-len(endCertificate)]
		if !bodies[strippedBody(body)] {
			continue
		}
		off = end
		// The line break that closed it came with it.
		if end < size {
			nl, err := isNewlineAt(f, end)
			if err != nil {
				return nil, err
			}
			if nl {
				end++
				off = end
			}
		}
		cuts = append(cuts, span{begin, end})
	}
	return cuts, nil
}

// findInFile returns the offset of needle at or after from, or -1. Each read
// carries len(needle)-1 bytes over, so a line on a chunk boundary still
// matches.
func findInFile(f io.ReaderAt, needle []byte, from, size int64) (int64, error) {
	buf := make([]byte, scanChunk+len(needle)-1)
	for off := from; off < size; {
		n, err := f.ReadAt(buf, off)
		if err != nil && err != io.EOF {
			return -1, err
		}
		if n < len(needle) {
			return -1, nil
		}
		if i := bytes.Index(buf[:n], needle); i != -1 {
			return off + int64(i), nil
		}
		off += int64(n - len(needle) + 1)
	}
	return -1, nil
}

func isNewlineAt(f io.ReaderAt, off int64) (bool, error) {
	var b [1]byte
	if _, err := f.ReadAt(b[:], off); err != nil {
		return false, err
	}
	return b[0] == '\n', nil
}

// closeGaps moves what the cuts left behind down over them, returning the size
// the caller then truncates to. Each run is copied over the gap the cuts before
// it opened, so the destination always trails the source and copying forwards
// never overwrites bytes still to be read.
func closeGaps(f bundleFile, cuts []span, size int64) (int64, error) {
	buf := make([]byte, scanChunk)
	var dst, src int64
	for _, cut := range cuts {
		moved, err := shiftDown(f, buf, src, cut.start, dst)
		dst += moved
		if err != nil {
			return 0, err
		}
		src = cut.end
	}
	moved, err := shiftDown(f, buf, src, size, dst)
	return dst + moved, err
}

// shiftDown copies from..to down to dst, returning how much it moved. The run
// before the first cut is already where it belongs and is left alone.
func shiftDown(f bundleFile, buf []byte, from, to, dst int64) (int64, error) {
	if dst == from {
		return to - from, nil
	}
	var moved int64
	for from < to {
		window := buf
		if left := to - from; left < int64(len(window)) {
			window = window[:left]
		}
		// The window is cut to what is left, so a short read is a file that
		// changed under the wrapper rather than the end of a run.
		n, err := f.ReadAt(window, from)
		if n > 0 {
			if _, werr := f.WriteAt(window[:n], dst); werr != nil {
				return moved, werr
			}
			from += int64(n)
			dst += int64(n)
			moved += int64(n)
		}
		if err != nil {
			return moved, err
		}
	}
	return moved, nil
}

// containerPathOf converts a path already resolved inside rootfs back to how
// the container itself sees it. The mount destination for a dirBind has to be
// this, not the candidate path's own directory: on RHEL the candidate is a
// symlink (/etc/pki/tls/certs/ca-bundle.crt) whose real file lives elsewhere
// (/etc/pki/ca-trust/extracted/pem/), and binding over the symlink's
// directory would shadow the wrong place.
func containerPathOf(rootfs, resolved string) string {
	if !withinRoot(rootfs, resolved) {
		return "/"
	}
	if rel := strings.TrimPrefix(resolved, rootfs); rel != "" {
		return rel
	}
	return "/"
}

// systemStore is the container's own CA bundle: where the wrapper reaches it
// from the host, and the path the container refers to it by. found stays false
// when the image ships no store at all, which is not fatal: it only changes
// what the otherwise-unset variables fall back to.
type systemStore struct {
	hostPath      string
	containerPath string
	found         bool
}

// dir is the directory a dirBind mirrors to reach the store.
func (s systemStore) dir() string {
	return filepath.Dir(s.hostPath)
}

func findSystemStore(rootfs string) (systemStore, error) {
	for _, candidate := range systemCertFiles {
		resolved, err := resolveInRoot(rootfs, candidate)
		if err != nil {
			continue
		}
		if _, err := os.Stat(resolved); err == nil {
			return systemStore{hostPath: resolved, containerPath: candidate, found: true}, nil
		}
	}
	return systemStore{}, errors.New("no CA bundle found in the rootfs")
}
