package macho

import (
	"encoding/binary"
	"fmt"

	"github.com/forgiverina/askua/pkg/logger"
)

func (a *ArchO) InjectDylib(weak bool, dylibPath string) error {
	ncmds := a.bo32(a.readU32At(16))
	off := int(a.headerSize)

	for i := uint32(0); i < ncmds; i++ {
		cmd := a.bo32(a.readU32At(off))
		cmdSize := a.bo32(a.readU32At(off + 4))

		if cmd == LCLoadDylib || cmd == LCLoadWeakDylib {
			nameOff := a.bo32(a.readU32At(off + 8))
			existing := nullString(a.data[off+int(nameOff):])
			if existing == dylibPath {
				wantCmd := uint32(LCLoadDylib)
				if weak {
					wantCmd = LCLoadWeakDylib
				}
				if cmd != wantCmd {
					a.putU32At(a.data, off, a.bo32(wantCmd))
				}
				return nil
			}
		}
		off += int(cmdSize)
	}

	nameLen := len(dylibPath)
	padding := 8 - nameLen%8
	cmdSize := 24 + nameLen + padding // sizeof(dylib_command) + name + pad

	if a.freeSpaceInCmds > 0 && uint32(cmdSize) > a.freeSpaceInCmds {
		return fmt.Errorf("not enough free space for dylib load command")
	}

	sizeofCmds := a.bo32(a.readU32At(20))
	insertAt := int(a.headerSize) + int(sizeofCmds)

	loadCmd := uint32(LCLoadDylib)
	if weak {
		loadCmd = LCLoadWeakDylib
	}

	a.putU32At(a.data, insertAt, a.bo32(loadCmd))
	a.putU32At(a.data, insertAt+4, a.bo32(uint32(cmdSize)))
	a.putU32At(a.data, insertAt+8, a.bo32(24)) // name offset from start of cmd
	a.putU32At(a.data, insertAt+12, a.bo32(2)) // timestamp
	a.putU32At(a.data, insertAt+16, 0)
	a.putU32At(a.data, insertAt+20, 0)

	nameBytes := make([]byte, nameLen+padding)
	copy(nameBytes, dylibPath)
	copy(a.data[insertAt+24:], nameBytes)

	ncmds++
	sizeofCmds += uint32(cmdSize)
	a.putU32At(a.data, 16, a.bo32(ncmds))
	a.putU32At(a.data, 20, a.bo32(sizeofCmds))
	return nil
}

func (a *ArchO) RemoveDylibs(dylibs map[string]struct{}) {
	ncmds := a.bo32(a.readU32At(16))
	sizeofCmds := a.bo32(a.readU32At(20))
	oldCmds := make([]byte, sizeofCmds)
	copy(oldCmds, a.data[a.headerSize:a.headerSize+sizeofCmds])

	var newCmds []byte
	removedCount := uint32(0)
	removedSize := uint32(0)

	off := 0
	for i := uint32(0); i < ncmds; i++ {
		cmd := a.bo32(binary.BigEndian.Uint32(oldCmds[off:]))
		cmdSize := a.bo32(binary.BigEndian.Uint32(oldCmds[off+4:]))

		if cmd == LCLoadDylib || cmd == LCLoadWeakDylib {
			nameOff := a.bo32(binary.BigEndian.Uint32(oldCmds[off+8:]))
			name := nullString(oldCmds[off+int(nameOff):])
			if _, remove := dylibs[name]; remove {
				logger.Printf("\t\t\t%s\tclear\n", name)
				removedCount++
				removedSize += cmdSize
				off += int(cmdSize)
				continue
			}
		}

		newCmds = append(newCmds, oldCmds[off:off+int(cmdSize)]...)
		off += int(cmdSize)
	}

	newArea := make([]byte, sizeofCmds)
	copy(newArea, newCmds)
	copy(a.data[a.headerSize:], newArea)

	a.putU32At(a.data, 16, a.bo32(ncmds-removedCount))
	a.putU32At(a.data, 20, a.bo32(sizeofCmds-removedSize))
}
