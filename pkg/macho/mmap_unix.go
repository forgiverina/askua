//go:build !windows

package macho

import (
	"os"

	"golang.org/x/sys/unix"
)

func mmapFile(f *os.File, size int) ([]byte, error) {
	return unix.Mmap(int(f.Fd()), 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
}

func unmapFile(data []byte) error {
	return unix.Munmap(data)
}

func msyncFile(data []byte) {
	_ = unix.Msync(data, unix.MS_SYNC)
}
