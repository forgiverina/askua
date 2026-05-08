package bundle

import (
	"crypto/sha1" //nolint:gosec
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

func isMachO(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var buf [4]byte
	if _, err := io.ReadFull(f, buf[:]); err != nil {
		return false
	}
	magic := binary.BigEndian.Uint32(buf[:])
	switch magic {
	case 0xcafebabe, 0xbebafeca,
		0xfeedface, 0xcefaedfe,
		0xfeedfacf, 0xcffaedfe:
		return true
	}
	return false
}

func fileHashes(path string) (sha1sum, sha256sum []byte, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	h1 := sha1.New() //nolint:gosec
	h256 := sha256.New()
	if _, err := io.Copy(io.MultiWriter(h1, h256), f); err != nil {
		return nil, nil, err
	}
	return h1.Sum(nil), h256.Sum(nil), nil
}

func sha1Hex(s string) string {
	h := sha1.Sum([]byte(s)) //nolint:gosec
	return fmt.Sprintf("%x", h)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}
