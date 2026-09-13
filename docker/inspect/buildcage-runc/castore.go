package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Markers delimit what this wrapper appended, so the removal is exact. A step
// that appends its own certificates afterwards, or that rewrites the file
// entirely, leaves the block either intact or absent; neither case damages the
// step's own content the way truncating to a remembered length would.
const (
	beginMarker = "# BEGIN buildcage CA"
	endMarker   = "# END buildcage CA"
)

// How much of a bundle removeCA holds at once. The store directory is a bind
// mount of the scratch mirror while the step runs, so the file is whatever
// size the step left it at, not what the image shipped.
const scanChunk = 64 << 10

// Same candidate order as buildkit's executor.InjectProxyCA.
var systemCertFiles = []string{
	"/etc/ssl/certs/ca-certificates.crt",
	"/etc/pki/tls/certs/ca-bundle.crt",
	"/etc/ssl/ca-bundle.pem",
	"/etc/pki/tls/cacert.pem",
	"/etc/ssl/cert.pem",
}

var errEscapesRoot = errors.New("path escapes the rootfs")

// errNotRegular means appendCA/removeCA found something other than a plain
// file at the target. The wrapper runs unsandboxed on the host, so opening
// whatever a step swapped the path for — a symlink, a FIFO — would follow
// attacker-controlled input outside the directory it's meant to stay in.
var errNotRegular = errors.New("not a regular file")

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
	if err != nil {
		return "", err
	}
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
			return "", errors.New("too many symlinks")
		}
		target, err := os.Readlink(next)
		if err != nil {
			return "", err
		}
		if filepath.IsAbs(target) {
			// Absolute inside the container means absolute inside the rootfs.
			current = rootfs
		}
		remaining = append(strings.Split(strings.TrimPrefix(filepath.Clean(target), "/"), "/"), remaining...)
	}
	if !withinRoot(rootfs, current) {
		return "", errEscapesRoot
	}
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

// appendCA adds the marked block to path, creating it when missing.
//
// O_NOFOLLOW/O_NONBLOCK keep the open from following a symlink or blocking on
// a FIFO the step may have left at path since injection.
func appendCA(path string, ca []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o644)
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
	block := fmt.Sprintf("\n%s\n%s\n%s\n", beginMarker, strings.TrimRight(string(ca), "\n"), endMarker)
	_, err = f.WriteString(block)
	return err
}

// removeCA deletes the marked block, leaving anything else in place.
//
// Returns without error when the block is absent, since the step may have
// rewritten the file itself. The find and the strip share one handle, opened
// the same guarded way as appendCA, so they can't land on different files.
func removeCA(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
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
	start, err := findInFile(f, []byte(beginMarker), 0, size)
	if err != nil {
		return err
	}
	if start == -1 {
		return nil
	}
	end, err := findInFile(f, []byte(endMarker), start, size)
	if err != nil {
		return err
	}
	if end == -1 {
		return nil
	}
	end += int64(len(endMarker))

	// Absorb the newline that opened the block and the one that closed it.
	if start > 0 {
		nl, err := isNewlineAt(f, start-1)
		if err != nil {
			return err
		}
		if nl {
			start--
		}
	}
	if end < size {
		nl, err := isNewlineAt(f, end)
		if err != nil {
			return err
		}
		if nl {
			end++
		}
	}

	if err := shiftDown(f, end, start, size); err != nil {
		return err
	}
	return f.Truncate(size - (end - start))
}

// findInFile returns the offset of needle at or after from, or -1. Each read
// carries len(needle)-1 bytes over, so a marker on a chunk boundary still
// matches.
func findInFile(f *os.File, needle []byte, from, size int64) (int64, error) {
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

func isNewlineAt(f *os.File, off int64) (bool, error) {
	var b [1]byte
	if _, err := f.ReadAt(b[:], off); err != nil {
		return false, err
	}
	return b[0] == '\n', nil
}

// shiftDown moves from..size down to to, leaving the caller to truncate. The
// destination trails the source, so copying forwards never overwrites bytes
// still to be read.
func shiftDown(f *os.File, from, to, size int64) error {
	buf := make([]byte, scanChunk)
	for from < size {
		n, err := f.ReadAt(buf, from)
		if n > 0 {
			if _, werr := f.WriteAt(buf[:n], to); werr != nil {
				return werr
			}
			from += int64(n)
			to += int64(n)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// containerPathOf converts a path already resolved inside rootfs back to how
// the container itself sees it. The mount destination for a dirBind has to be
// this, not the candidate path's own directory: on RHEL the candidate is a
// symlink (/etc/pki/tls/certs/ca-bundle.crt) whose real file lives elsewhere
// (/etc/pki/ca-trust/extracted/pem/), and binding over the symlink's
// directory would shadow the wrong place.
func containerPathOf(rootfs, resolved string) string {
	if !strings.HasPrefix(resolved, rootfs) {
		return "/"
	}
	if rel := strings.TrimPrefix(resolved, rootfs); rel != "" {
		return rel
	}
	return "/"
}

// findSystemStore returns the container's own CA bundle, as a path inside the
// rootfs and as the path the container refers to it by.
func findSystemStore(rootfs string) (hostPath, containerPath string, err error) {
	for _, candidate := range systemCertFiles {
		resolved, err := resolveInRoot(rootfs, candidate)
		if err != nil {
			continue
		}
		if _, err := os.Stat(resolved); err == nil {
			return resolved, candidate, nil
		}
	}
	return "", "", errors.New("no CA bundle found in the rootfs")
}
