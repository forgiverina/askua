package macho

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/forgiverina/askua/pkg/cert"
	"github.com/forgiverina/askua/pkg/codesign"
	"github.com/forgiverina/askua/pkg/logger"
	"go.mozilla.org/pkcs7"
)

var execSegLimit uint64

type ArchO struct {
	data []byte

	codeLength uint32
	signOffset uint32
	signLength uint32

	infoPlist   string
	encrypted   bool
	is64        bool
	bigEndian   bool
	enoughSpace bool

	codeSignCmdOffset int
	linkeditOffset    int
	freeSpaceInCmds   uint32

	fileType   uint32
	headerSize uint32
}

func (a *ArchO) Init(data []byte) error {
	if len(data) < 8 {
		return fmt.Errorf("data too short")
	}

	a.data = data
	a.enoughSpace = true
	a.codeSignCmdOffset = -1
	a.linkeditOffset = -1

	magic := a.readU32(0)
	switch magic {
	case MHMagic, MHCigam, MHMagic64, MHCigam64:
	default:
		return fmt.Errorf("not a Mach-O binary (magic=0x%08x)", magic)
	}

	a.bigEndian = magic == MHCigam || magic == MHCigam64
	a.is64 = magic == MHMagic64 || magic == MHCigam64

	if a.is64 {
		a.headerSize = 32 // sizeof(mach_header_64)
	} else {
		a.headerSize = 28 // sizeof(mach_header)
	}

	a.fileType = a.bo32(a.readU32(12))
	ncmds := a.bo32(a.readU32(16))

	// default code length is total size aligned to 16
	a.codeLength = uint32(len(data))
	if a.codeLength%16 != 0 {
		a.codeLength = a.codeLength + 16 - (a.codeLength % 16)
	}

	off := int(a.headerSize)
	for i := uint32(0); i < ncmds; i++ {
		if off+8 > len(data) {
			break
		}
		cmd := a.bo32(a.readU32At(off))
		cmdSize := a.bo32(a.readU32At(off + 4))

		switch cmd {
		case LCSegment:
			if off+56 <= len(data) {
				segName := nullString(data[off+8 : off+24])
				switch segName {
				case "__TEXT":
					execSegLimit = uint64(a.bo32(a.readU32At(off + 28))) // vmsize
					nsects := a.bo32(a.readU32At(off + 48))
					sectBase := off + 56 // sizeof(segment_command)
					for j := uint32(0); j < nsects; j++ {
						sOff := sectBase + int(j)*68 // sizeof(section)
						if sOff+68 > len(data) {
							break
						}
						sectName := nullString(data[sOff : sOff+16])
						switch sectName {
						case "__text":
							sectOffset := a.bo32(a.readU32At(sOff + 40))
							sizeofCmds := a.bo32(a.readU32At(20))
							if sectOffset > sizeofCmds+a.headerSize {
								a.freeSpaceInCmds = sectOffset - sizeofCmds - a.headerSize
							}
						case "__info_plist":
							plistOff := a.bo32(a.readU32At(sOff + 40))
							plistSize := a.bo32(a.readU32At(sOff + 44))
							if int(plistOff)+int(plistSize) <= len(data) {
								a.infoPlist = string(data[plistOff : plistOff+plistSize])
							}
						}
					}
				case "__LINKEDIT":
					a.linkeditOffset = off
				}
			}
		case LCSegment64:
			if off+72 <= len(data) {
				segName := nullString(data[off+8 : off+24])
				switch segName {
				case "__TEXT":
					execSegLimit = a.bo64(a.readU64At(off + 32)) // vmsize
					nsects := a.bo32(a.readU32At(off + 64))
					sectBase := off + 72 // sizeof(segment_command_64)
					for j := uint32(0); j < nsects; j++ {
						sOff := sectBase + int(j)*80 // sizeof(section_64)
						if sOff+80 > len(data) {
							break
						}
						sectName := nullString(data[sOff : sOff+16])
						switch sectName {
						case "__text":
							sectOffset := a.bo32(a.readU32At(sOff + 48))
							sizeofCmds := a.bo32(a.readU32At(20))
							if sectOffset > sizeofCmds+a.headerSize {
								a.freeSpaceInCmds = sectOffset - sizeofCmds - a.headerSize
							}
						case "__info_plist":
							plistOff := a.bo32(a.readU32At(sOff + 48))
							plistSize := uint32(a.bo64(a.readU64At(sOff + 40)))
							if int(plistOff)+int(plistSize) <= len(data) {
								a.infoPlist = string(data[plistOff : plistOff+plistSize])
							}
						}
					}
				case "__LINKEDIT":
					a.linkeditOffset = off
				}
			}
		case LCEncryptionInfo, LCEncryptionInfo64:
			if off+20 <= len(data) {
				cryptID := a.bo32(a.readU32At(off + 16))
				if cryptID >= 1 {
					a.encrypted = true
				}
			}
		case LCCodeSignature:
			if off+16 <= len(data) {
				a.codeSignCmdOffset = off
				dataOff := a.bo32(a.readU32At(off + 8))
				dataSize := a.bo32(a.readU32At(off + 12))
				a.codeLength = dataOff
				a.signOffset = dataOff
				a.signLength = dataSize
			}
		}

		off += int(cmdSize)
	}

	return nil
}

func (a *ArchO) IsExecute() bool {
	return a.fileType == MHExecute
}

func (a *ArchO) IsSigned() bool {
	return a.signOffset > 0 && a.signLength > 0
}

func (a *ArchO) InfoPlist() string {
	return a.infoPlist
}

func (a *ArchO) PrintInfo() {
	cpuType := int32(a.bo32(a.readU32At(4)))
	cpuSubtype := int32(a.bo32(a.readU32At(8)))
	ncmds := a.bo32(a.readU32At(16))

	logger.Printf("------------------------------------------------------------------\n")
	logger.Printf("- MachO Info: \n")
	logger.Printf("\tFileType: \t%s\n", GetFileTypeName(a.fileType))
	logger.Printf("\tTotalSize: \t%d (%s)\n", len(a.data), formatSize(int64(len(a.data))))
	logger.Printf("\tPlatform: \t%d\n", map[bool]int{true: 64, false: 32}[a.is64])
	logger.Printf("\tCPUArch: \t%s\n", GetArchName(cpuType, cpuSubtype))
	logger.Printf("\tCPUType: \t0x%x\n", cpuType)
	logger.Printf("\tCPUSubType: \t0x%x\n", cpuSubtype)
	logger.Printf("\tBigEndian: \t%v\n", a.bigEndian)
	logger.Printf("\tEncrypted: \t%v\n", a.encrypted)
	logger.Printf("\tCommandCount: \t%d\n", ncmds)
	logger.Printf("\tCodeLength: \t%d (%s)\n", a.codeLength, formatSize(int64(a.codeLength)))
	logger.Printf("\tSignLength: \t%d (%s)\n", a.signLength, formatSize(int64(a.signLength)))
	spare := int64(len(a.data)) - int64(a.codeLength) - int64(a.signLength)
	logger.Printf("\tSpareLength: \t%d (%s)\n", spare, formatSize(spare))

	off := int(a.headerSize)
	for i := uint32(0); i < ncmds; i++ {
		cmd := a.bo32(a.readU32At(off))
		cmdSize := a.bo32(a.readU32At(off + 4))
		switch cmd {
		case LCVersionMinIPhone:
			logger.Printf("\tMIN_IPHONEOS: \t0x%x\n", a.bo32(a.readU32At(off+8)))
		case LCRPath:
			nameOff := a.bo32(a.readU32At(off + 8))
			rpath := nullString(a.data[off+int(nameOff):])
			logger.Printf("\tLC_RPATH: \t%s\n", rpath)
		case LCLoadDylib, LCLoadWeakDylib:
			nameOff := a.bo32(a.readU32At(off + 8))
			dylib := nullString(a.data[off+int(nameOff):])
			if cmd == LCLoadDylib {
				logger.Printf("\t\t\t%s\n", dylib)
			} else {
				logger.Printf("\t\t\t%s (weak)\n", dylib)
			}
		}
		off += int(cmdSize)
	}

	if a.infoPlist != "" {
		logger.Printf("\n- Embedded Info.plist: \n")
		logger.Printf("\tlength: \t%d\n", len(a.infoPlist))
		content := strings.ReplaceAll(a.infoPlist, "\n", "\n\t\t\t")
		logger.Printf("\tcontent: \t%s\n", content)
		sha1sum := sha1.Sum([]byte(a.infoPlist))
		sha256sum := sha256.Sum256([]byte(a.infoPlist))
		logger.Printf("\tSHA-1:  \t%x\n", sha1sum)
		logger.Printf("\tSHA-256:\t%x\n", sha256sum)
	}

	if a.signOffset == 0 {
		logger.Warn("- Can't find CodeSignature segment!\n")
	} else {
		codesign.ParseCodeSignature(a.data[a.signOffset:])
	}
	logger.Printf("------------------------------------------------------------------\n")
}

func (a *ArchO) Sign(asset *cert.Asset, force bool, bundleID, infoSHA1, infoSHA256, codeResData string) error {
	if a.signOffset == 0 {
		a.enoughSpace = false
		return fmt.Errorf("no LC_CODE_SIGNATURE load command found")
	}

	var codeResSHA1, codeResSHA256 []byte
	if codeResData == "" {
		codeResSHA1 = make([]byte, 20)
		codeResSHA256 = make([]byte, 32)
	} else {
		h1 := sha1.Sum([]byte(codeResData))
		h256 := sha256.Sum256([]byte(codeResData))
		codeResSHA1 = h1[:]
		codeResSHA256 = h256[:]
	}

	blob, err := a.buildCodeSignature(asset, force, bundleID, infoSHA1, infoSHA256, codeResSHA1, codeResSHA256)
	if err != nil {
		return fmt.Errorf("build code signature: %w", err)
	}

	available := int(len(a.data)) - int(a.codeLength)
	if len(blob) > available {
		a.enoughSpace = false
		return fmt.Errorf("insufficient signature space: have %d, need %d", available, len(blob))
	}

	copy(a.data[a.codeLength:], blob)
	return nil
}

func (a *ArchO) buildCodeSignature(asset *cert.Asset, force bool, bundleID, infoSHA1, infoSHA256 string, codeResSHA1, codeResSHA256 []byte) ([]byte, error) {
	emptyEntitlements := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict/>
</plist>
`

	entitleData := asset.EntitleData
	if !a.IsExecute() {
		entitleData = emptyEntitlements
	}

	reqSlot := codesign.BuildRequirements(bundleID, asset.SubjectCN)
	entSlot := codesign.BuildEntitlements(entitleData)

	derEntitleData := entitleData
	if !a.IsExecute() {
		derEntitleData = ""
	}
	derSlot, _ := codesign.BuildDEREntitlements(derEntitleData)

	hashOf := func(b []byte) (sha1hash, sha256hash []byte) {
		if len(b) == 0 {
			return make([]byte, 20), make([]byte, 32)
		}
		h1 := sha1.Sum(b)
		h256 := sha256.Sum256(b)
		return h1[:], h256[:]
	}

	reqSHA1, reqSHA256 := hashOf(reqSlot)
	entSHA1, entSHA256 := hashOf(entSlot)
	derSHA1, derSHA256 := hashOf(derSlot)

	var existCodeSlots1, existCodeSlots256 []byte
	if !force && a.signOffset > 0 {
		existCodeSlots1, existCodeSlots256 = codesign.ExtractCodeSlots(a.data[a.signOffset:])
	}

	execSegFlags := uint64(0)
	if a.fileType == MHExecute {
		if asset.Adhoc || asset.SingleBinary {
			execSegFlags = CSExecSegMainBinary
		}
	}
	if len(entSlot) > 8 && strings.Contains(string(entSlot[8:]), "<key>get-task-allow</key>") {
		execSegFlags |= CSExecSegMainBinary | CSExecSegAllowUnsigned
	}

	params := codesign.CDParams{
		CodeBase:         a.data[:a.codeLength],
		ExecSegLimit:     execSegLimit,
		ExecSegFlags:     execSegFlags,
		BundleID:         bundleID,
		TeamID:           asset.TeamID,
		InfoPlistSHA1:    []byte(infoSHA1),
		InfoPlistSHA256:  []byte(infoSHA256),
		ReqSlotSHA1:      reqSHA1,
		ReqSlotSHA256:    reqSHA256,
		CodeResSHA1:      codeResSHA1,
		CodeResSHA256:    codeResSHA256,
		EntSlotSHA1:      entSHA1,
		EntSlotSHA256:    entSHA256,
		DEREntSlotSHA1:   derSHA1,
		DEREntSlotSHA256: derSHA256,
		IsExecute:        a.IsExecute(),
		IsAdhoc:          asset.Adhoc,
	}

	precomputedSHA1, precomputedSHA256 := codesign.ComputePageHashes(a.data[:a.codeLength])

	var cdSlot1, cdSlot256 []byte
	var err error

	if !asset.SHA256Only {
		if len(existCodeSlots1) > 0 {
			params.ExistingCodeSlots = existCodeSlots1
		} else {
			params.ExistingCodeSlots = precomputedSHA1
		}
		cdSlot1, err = codesign.BuildCodeDirectory(false, params)
		if err != nil {
			return nil, fmt.Errorf("build sha1 code directory: %w", err)
		}
	}

	if len(existCodeSlots256) > 0 {
		params.ExistingCodeSlots = existCodeSlots256
	} else {
		params.ExistingCodeSlots = precomputedSHA256
	}
	cdSlot256, err = codesign.BuildCodeDirectory(true, params)
	if err != nil {
		return nil, fmt.Errorf("build sha256 code directory: %w", err)
	}

	if asset.SHA256Only {
		cdSlot1, cdSlot256 = cdSlot256, nil
	}

	var cmsSlot []byte
	if !asset.Adhoc {
		cmsSlot, err = codesign.BuildCMSSignature(asset, cdSlot1, cdSlot256)
		if err != nil {
			return nil, fmt.Errorf("build CMS signature: %w", err)
		}
	}

	return codesign.BuildSuperBlob(cdSlot1, reqSlot, entSlot, derSlot, cdSlot256, cmsSlot), nil
}

func (a *ArchO) GetSigningCert() *x509.Certificate {
	if a.signOffset == 0 || a.signLength == 0 {
		return nil
	}
	end := int(a.signOffset) + int(a.signLength)
	if end > len(a.data) {
		return nil
	}
	sig := a.data[a.signOffset:end]

	if len(sig) < 12 {
		return nil
	}
	magic := binary.BigEndian.Uint32(sig[0:4])
	if magic != CSMagicEmbeddedSignature {
		return nil
	}
	count := int(binary.BigEndian.Uint32(sig[8:12]))
	for i := 0; i < count; i++ {
		base := 12 + i*8
		if base+8 > len(sig) {
			break
		}
		slotType := binary.BigEndian.Uint32(sig[base:])
		slotOff := int(binary.BigEndian.Uint32(sig[base+4:]))
		if slotType != CSSlotSignatureSlot {
			continue
		}
		if slotOff+8 > len(sig) {
			break
		}
		blobLen := int(binary.BigEndian.Uint32(sig[slotOff+4:]))
		if slotOff+blobLen > len(sig) || blobLen <= 8 {
			break
		}
		cmsData := sig[slotOff+8 : slotOff+blobLen]
		p7, err := pkcs7.Parse(cmsData)
		if err != nil || len(p7.Certificates) == 0 {
			break
		}
		for _, c := range p7.Certificates {
			if !c.IsCA {
				return c
			}
		}
		return p7.Certificates[0]
	}
	return nil
}

func (a *ArchO) readU32(off int) uint32 {
	return binary.BigEndian.Uint32(a.data[off:])
}

func (a *ArchO) readU32At(off int) uint32 {
	return binary.BigEndian.Uint32(a.data[off:])
}

func (a *ArchO) readU64At(off int) uint64 {
	return binary.BigEndian.Uint64(a.data[off:])
}

func (a *ArchO) putU32At(dst []byte, off int, val uint32) {
	binary.BigEndian.PutUint32(dst[off:], val)
}

func (a *ArchO) bo32(val uint32) uint32 {
	if a.bigEndian {
		return swapU32(val)
	}
	return val
}

func (a *ArchO) bo64(val uint64) uint64 {
	if a.bigEndian {
		return swapU64(val)
	}
	return val
}

func swapU32(v uint32) uint32 {
	return (v>>24)&0xff | (v>>8)&0xff00 | (v<<8)&0xff0000 | (v<<24)&0xff000000
}

func swapU64(v uint64) uint64 {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return binary.LittleEndian.Uint64(b)
}

func nullString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

func formatSize(n int64) string {
	const k = 1024
	switch {
	case n >= k*k*k:
		return fmt.Sprintf("%.2f GB", float64(n)/float64(k*k*k))
	case n >= k*k:
		return fmt.Sprintf("%.2f MB", float64(n)/float64(k*k))
	case n >= k:
		return fmt.Sprintf("%.2f KB", float64(n)/float64(k))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
