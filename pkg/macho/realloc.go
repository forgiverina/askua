package macho

import (
	"encoding/binary"
	"fmt"
	"os"

	"github.com/forgiverina/askua/pkg/codesign"
)

func (a *ArchO) ReallocCodeSignSpace(newFile string) (uint32, error) {
	_ = os.Remove(newFile)

	pages := (a.codeLength / 4096) + 1
	extra := codesign.AlignUp(pages*(20+32), 4096) + 32768
	newLength := a.codeLength + extra

	if a.linkeditOffset < 0 {
		return 0, fmt.Errorf("no __LINKEDIT segment")
	}
	if newLength <= uint32(len(a.data)) {
		if err := os.WriteFile(newFile, a.data, 0755); err != nil {
			return 0, err
		}
		return uint32(len(a.data)), nil
	}

	localData := make([]byte, len(a.data))
	copy(localData, a.data)

	cmd := a.bo32(binary.BigEndian.Uint32(localData[a.linkeditOffset:]))
	if cmd == LCSegment {
		// 32-bit: vmsize@+28, fileoff@+32, filesize@+36
		vmsize := a.bo32(binary.BigEndian.Uint32(localData[a.linkeditOffset+28:]))
		newVMSize := codesign.AlignUp(vmsize+(newLength-uint32(len(localData))), 4096)
		a.putU32At(localData, a.linkeditOffset+28, a.bo32(newVMSize))
		fileoff := a.bo32(binary.BigEndian.Uint32(localData[a.linkeditOffset+32:]))
		a.putU32At(localData, a.linkeditOffset+36, a.bo32(newLength-fileoff))
	} else if cmd == LCSegment64 {
		// vmsize@+32, fileoff@+40, filesize@+48; read/write only the low 4 bytes of each uint64 field.
		vmsize := a.bo32(binary.BigEndian.Uint32(localData[a.linkeditOffset+32:]))
		newVMSize := codesign.AlignUp(vmsize+(newLength-uint32(len(localData))), 4096)
		a.putU32At(localData, a.linkeditOffset+32, a.bo32(newVMSize))
		fileoff := a.bo32(binary.BigEndian.Uint32(localData[a.linkeditOffset+40:]))
		a.putU32At(localData, a.linkeditOffset+48, a.bo32(newLength-fileoff))
	}

	if a.codeSignCmdOffset >= 0 {
		a.putU32At(localData, a.codeSignCmdOffset+12, a.bo32(newLength-a.codeLength))
	} else {
		if a.freeSpaceInCmds < 16 {
			return 0, fmt.Errorf("no free space in load commands for LC_CODE_SIGNATURE")
		}
		ncmds := a.bo32(binary.BigEndian.Uint32(localData[16:]))
		sizeofCmds := a.bo32(binary.BigEndian.Uint32(localData[20:]))
		insertAt := int(a.headerSize) + int(sizeofCmds)
		binary.BigEndian.PutUint32(localData[insertAt:], a.bo32(LCCodeSignature))
		binary.BigEndian.PutUint32(localData[insertAt+4:], a.bo32(16))
		binary.BigEndian.PutUint32(localData[insertAt+8:], a.bo32(a.codeLength))
		binary.BigEndian.PutUint32(localData[insertAt+12:], a.bo32(newLength-a.codeLength))
		binary.BigEndian.PutUint32(localData[16:], a.bo32(ncmds+1))
		binary.BigEndian.PutUint32(localData[20:], a.bo32(sizeofCmds+16))
	}

	padding := make([]byte, newLength-uint32(len(localData)))
	combined := append(localData, padding...)
	if err := os.WriteFile(newFile, combined, 0755); err != nil {
		return 0, err
	}
	return newLength, nil
}
