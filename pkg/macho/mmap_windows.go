//go:build windows

package macho

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func mmapFile(f *os.File, size int) ([]byte, error) {
	h, err := windows.CreateFileMapping(
		windows.Handle(f.Fd()), nil,
		windows.PAGE_READWRITE, 0, uint32(size), nil,
	)
	if err != nil {
		return nil, fmt.Errorf("CreateFileMapping: %w", err)
	}
	defer windows.CloseHandle(h)

	ptr, err := windows.MapViewOfFile(
		h, windows.FILE_MAP_READ|windows.FILE_MAP_WRITE,
		0, 0, uintptr(size),
	)
	if err != nil {
		return nil, fmt.Errorf("MapViewOfFile: %w", err)
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(ptr)), size), nil
}

func unmapFile(data []byte) error {
	return windows.UnmapViewOfFile(uintptr(unsafe.Pointer(&data[0])))
}

func msyncFile(data []byte) {
	_ = windows.FlushViewOfFile(uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)))
}
