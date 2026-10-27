package ui

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Limits for the recursive download (key: D). They exist so that pointing it
// at a multi-terabyte share, or at a directory loop a server invents, ends
// in a bounded, explainable stop instead of filling the disk.
const (
	treeMaxFiles = 5000
	treeMaxBytes = int64(4) << 30
	treeMaxDepth = 12
)

// treeResult summarises a recursive download.
type treeResult struct {
	files   int
	bytes   int64
	skipped int
	// note is why it stopped early or the first problem it skipped past.
	note string
}

type treeJob struct {
	remote string
	local  string
	depth  int
}

// downloadTree copies remoteRoot and everything below it into localRoot,
// within the limits above. Unreadable entries are skipped and counted; a
// cancelled context stops it between (and during) files.
func downloadTree(ctx context.Context, fs remoteFS, remoteRoot, localRoot string, st *downloadState) treeResult {
	var res treeResult
	note := func(s string) {
		if res.note == "" {
			res.note = s
		}
	}

	stack := []treeJob{{remote: remoteRoot, local: localRoot}}
	for len(stack) > 0 {
		if ctx.Err() != nil {
			res.note = "cancelled"
			return res
		}
		job := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		entries, err := fs.List(ctx, job.remote)
		if err != nil {
			res.skipped++
			note(prettyFS(err.Error()))
			continue
		}
		for _, e := range entries {
			if e.up || e.Pipe || e.Name == "" {
				continue
			}
			remote := joinRemote(job.remote, e.Name)
			local := filepath.Join(job.local, sanitizeName(e.Name))

			if e.Dir {
				if job.depth+1 > treeMaxDepth {
					res.skipped++
					note(fmt.Sprintf("deeper than %d levels", treeMaxDepth))
					continue
				}
				stack = append(stack, treeJob{remote: remote, local: local, depth: job.depth + 1})
				continue
			}

			if res.files >= treeMaxFiles {
				res.note = fmt.Sprintf("stopped at %d files", treeMaxFiles)
				return res
			}
			if res.bytes+e.Size > treeMaxBytes {
				res.skipped++
				note(fmt.Sprintf("%s limit reached", humanSize(treeMaxBytes)))
				continue
			}

			n, err := copyRemoteFile(ctx, fs, remote, local, st)
			if err != nil {
				if ctx.Err() != nil {
					res.note = "cancelled"
					return res
				}
				res.skipped++
				note(prettyFS(err.Error()))
				continue
			}
			res.files++
			res.bytes += n
			st.files.Add(1)
		}
	}
	return res
}

// copyRemoteFile streams one file to dest (via dest.part, then rename),
// never overwriting an existing local file.
func copyRemoteFile(ctx context.Context, fs remoteFS, remote, dest string, st *downloadState) (int64, error) {
	rc, size, err := fs.Open(ctx, remote)
	if err != nil {
		return 0, err
	}
	defer rc.Close()

	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return 0, err
	}
	dest = uniquePath(dest)
	tmp := dest + ".part"
	f, err := os.Create(tmp)
	if err != nil {
		return 0, err
	}
	if size > 0 {
		st.total.Add(size)
	}
	pr := &progressReader{r: &ctxReader{ctx: ctx, r: rc}, st: st}
	n, err := io.CopyBuffer(f, pr, make([]byte, 256*1024))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return n, err
	}
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		return n, err
	}
	return n, nil
}

// ctxReader aborts a copy as soon as its context is cancelled.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c *ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// uniquePath returns dest, or "name (1).ext", "name (2).ext", ... when it
// already exists. The extension comes from the file name alone: a host IP in
// the directory part has dots too.
func uniquePath(dest string) string {
	dir, file := filepath.Split(dest)
	base, ext := file, ""
	if i := strings.LastIndex(file, "."); i > 0 {
		base, ext = file[:i], file[i:]
	}
	for i := 1; exists(dest); i++ {
		dest = filepath.Join(dir, fmt.Sprintf("%s (%d)%s", base, i, ext))
		if i > 500 {
			break
		}
	}
	return dest
}
