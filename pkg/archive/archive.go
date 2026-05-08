package archive

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/klauspost/compress/flate"
	"github.com/klauspost/compress/zip"
)

func IsZipFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var buf [2]byte
	if _, err := io.ReadFull(f, buf[:]); err != nil {
		return false
	}
	return buf[0] == 'P' && buf[1] == 'K'
}

func Archive(folder, zipFile string, level int) error {
	if level < 0 || level > 9 {
		return fmt.Errorf("invalid compression level %d (must be 0–9)", level)
	}

	out, err := os.Create(zipFile)
	if err != nil {
		return fmt.Errorf("create zip %s: %w", zipFile, err)
	}
	defer out.Close()

	zw := zip.NewWriter(out)
	defer zw.Close()

	if level > 0 {
		zw.RegisterCompressor(zip.Deflate, func(w io.Writer) (io.WriteCloser, error) {
			return flate.NewWriter(w, level)
		})
	}

	err = filepath.WalkDir(folder, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(folder, path)
		if err != nil {
			return err
		}
		relPath = filepath.ToSlash(relPath)

		if relPath == "." {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		hdr, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		hdr.Name = relPath

		if d.IsDir() {
			hdr.Name += "/"
			hdr.Method = zip.Store
			_, err = zw.CreateHeader(hdr)
			return err
		}

		if level == 0 {
			hdr.Method = zip.Store
		} else {
			hdr.Method = zip.Deflate
		}

		w, err := zw.CreateHeader(hdr)
		if err != nil {
			return fmt.Errorf("create zip entry %s: %w", relPath, err)
		}

		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open %s: %w", path, err)
		}
		defer f.Close()

		if _, err := io.Copy(w, f); err != nil {
			return fmt.Errorf("write zip entry %s: %w", relPath, err)
		}
		return nil
	})

	return err
}

func Extract(zipFile, outputFolder string) error {
	_ = os.RemoveAll(outputFolder)

	r, err := zip.OpenReader(zipFile)
	if err != nil {
		return fmt.Errorf("open zip %s: %w", zipFile, err)
	}
	defer r.Close()

	type fileJob struct {
		f    *zip.File
		dest string
	}
	var files []fileJob

	for _, f := range r.File {
		if !isPathSafe(f.Name) {
			continue
		}
		dest := filepath.Join(outputFolder, filepath.FromSlash(f.Name))
		if f.FileInfo().IsDir() || strings.HasSuffix(f.Name, "/") {
			if err := os.MkdirAll(dest, 0755); err != nil {
				return fmt.Errorf("mkdir %s: %w", dest, err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
			return fmt.Errorf("mkdir parent %s: %w", dest, err)
		}
		files = append(files, fileJob{f, dest})
	}

	if len(files) == 0 {
		return nil
	}

	numWorkers := runtime.NumCPU()
	if numWorkers > 8 {
		numWorkers = 8
	}
	if numWorkers > len(files) {
		numWorkers = len(files)
	}

	jobs := make(chan fileJob, numWorkers*2)
	errCh := make(chan error, numWorkers)
	var wg sync.WaitGroup

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 512*1024)
			for job := range jobs {
				if err := extractFile(job.f, job.dest, buf); err != nil {
					select {
					case errCh <- err:
					default:
					}
					return
				}
			}
		}()
	}

	var firstErr error
outer:
	for _, job := range files {
		select {
		case jobs <- job:
		case err := <-errCh:
			firstErr = err
			break outer
		}
	}
	close(jobs)
	wg.Wait()

	if firstErr == nil {
		select {
		case firstErr = <-errCh:
		default:
		}
	}

	if firstErr != nil {
		_ = os.RemoveAll(outputFolder)
		return firstErr
	}
	return nil
}

func extractFile(f *zip.File, dest string, buf []byte) error {
	rc, err := f.Open()
	if err != nil {
		return fmt.Errorf("open zip entry %s: %w", f.Name, err)
	}
	defer rc.Close()

	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
	if err != nil {
		return fmt.Errorf("create %s: %w", dest, err)
	}
	defer out.Close()

	if _, err = io.CopyBuffer(out, rc, buf); err != nil {
		return fmt.Errorf("write %s: %w", dest, err)
	}
	return nil
}

func isPathSafe(name string) bool {
	if name == "" || name[0] == '/' {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return false
		}
	}
	return true
}

func FormatSize(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return "?"
	}
	return formatBytes(info.Size())
}

func formatBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
