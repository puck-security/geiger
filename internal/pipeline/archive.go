package pipeline

import (
	"bytes"
	"context"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/mholt/archives"
	"github.com/puck-security/geiger/internal/parse"
)

// Archive limits. IR is routinely handed a tarball of a compromised host, so an
// archive is a first-class input — but it is also attacker-supplied, and a
// decompression bomb is a few KB on disk. Every expansion is bounded by all
// four of these at once.
const (
	maxArchiveDepth   = 2         // an archive inside an archive, no deeper
	maxArchiveMembers = 5000      // members read per top-level archive
	maxArchiveBytes   = 256 << 20 // total decompressed bytes per top-level archive
)

// archiveExts gates which files geiger tries to open as containers. Sniffing
// every file's header instead would cost a read per file across the whole walk;
// the extension narrows it, and archives.Identify still has the final say.
var archiveExts = map[string]bool{
	".zip": true, ".jar": true, ".tar": true, ".tgz": true, ".tbz2": true,
	".txz": true, ".gz": true, ".bz2": true, ".xz": true, ".7z": true,
	".rar": true, ".br": true, ".zst": true, ".lz4": true,
}

// looksLikeArchive reports whether a filename should be opened as a container.
func looksLikeArchive(name string) bool {
	return archiveExts[strings.ToLower(filepath.Ext(name))]
}

// SourcesFromArchive expands path as an archive, reporting whether it was
// handled as one. A file named directly on the command line goes through here so
// that `geiger host.tar.gz` behaves like a walk of the tree inside it — being
// handed a tarball of a compromised host is the common IR case.
//
// A file whose name says archive but whose contents don't parse as one is
// reported as unhandled, so the caller falls back to reading it as plain text.
func SourcesFromArchive(path string) ([]Source, bool) {
	if !looksLikeArchive(path) {
		return nil, false
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Size() > maxArchiveBytes {
		return nil, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	srcs := archiveSources(path, data)
	if len(srcs) == 0 {
		return nil, false
	}
	for i := range srcs {
		srcs[i].Blob.ModTime = fi.ModTime()
	}
	return srcs, true
}

// archiveBudget bounds one top-level expansion, including nested archives.
type archiveBudget struct {
	members int
	bytes   int64
}

func (b *archiveBudget) take(n int64) bool {
	if b.members >= maxArchiveMembers || b.bytes+n > maxArchiveBytes {
		return false
	}
	b.members++
	b.bytes += n
	return true
}

// archiveSources expands one archive into a Source per member. Members are
// returned in archive order, so a scan of the same file always triages them in
// the same order. Anything unreadable, oversized, or past a limit is skipped
// rather than failing the archive — a partially corrupt tarball off a
// compromised host should still yield the members that do read.
//
// Member labels are "<archive path>::<member path>", so a finding names the file
// it came from inside the container it was shipped in.
func archiveSources(path string, raw []byte) []Source {
	var out []Source
	b := &archiveBudget{}
	expandArchive(context.Background(), path, raw, 0, b, &out)
	return out
}

func expandArchive(ctx context.Context, label string, raw []byte, depth int, b *archiveBudget, out *[]Source) {
	format, stream, err := archives.Identify(ctx, filepath.Base(label), bytes.NewReader(raw))
	if err != nil {
		return // not an archive after all, or an unknown format
	}
	switch f := format.(type) {
	case archives.Extractor:
		_ = f.Extract(ctx, stream, func(ctx context.Context, info archives.FileInfo) error {
			if info.IsDir() || info.LinkTarget != "" {
				return nil // no contents of their own
			}
			// The name comes from the archive and is not trustworthy. Nothing is
			// written to disk, so this only has to produce an honest label.
			name := path.Clean("/" + info.NameInArchive)[1:]
			if name == "" || skipFile(path.Base(name)) {
				return nil
			}
			size := info.Size()
			if size > maxFileSize || !b.take(size) {
				return nil
			}
			data, err := readMember(info)
			if err != nil {
				return nil
			}
			addMember(ctx, label+"::"+name, data, depth, b, out)
			return nil
		})
	case archives.Decompressor:
		// A single compressed file (access.log.gz), not a container.
		rc, err := f.OpenReader(stream)
		if err != nil {
			return
		}
		defer rc.Close()
		data, err := readCapped(rc)
		if err != nil || !b.take(int64(len(data))) {
			return
		}
		addMember(ctx, strings.TrimSuffix(label, filepath.Ext(label)), data, depth, b, out)
	}
}

// addMember turns one extracted member into a Source, recursing when the member
// is itself an archive and depth allows.
func addMember(ctx context.Context, label string, data []byte, depth int, b *archiveBudget, out *[]Source) {
	if looksLikeArchive(label) && depth+1 <= maxArchiveDepth {
		expandArchive(ctx, label, data, depth+1, b, out)
		return
	}
	*out = append(*out, Source{Label: label, Blob: parse.Parse(string(data), label)})
}

func readMember(info archives.FileInfo) ([]byte, error) {
	f, err := info.Open()
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readCapped(f)
}

// readCapped reads at most maxFileSize bytes, reporting an error past the cap so
// a member that lies about its size in the header is still bounded.
func readCapped(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxFileSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxFileSize {
		return nil, io.ErrShortBuffer
	}
	return data, nil
}
