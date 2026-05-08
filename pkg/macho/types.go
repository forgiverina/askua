package macho

const (
	CPUArchMask    = 0xff000000
	CPUArchABI64   = 0x01000000
	CPUArchABI6432 = 0x02000000

	CPUTypeAny     = -1
	CPUTypeX86     = 7
	CPUTypeI386    = CPUTypeX86
	CPUTypeARM     = 12
	CPUTypePowerPC = 18
	CPUTypeX86_64  = CPUTypeX86 | CPUArchABI64
	CPUTypeARM64   = CPUTypeARM | CPUArchABI64
	CPUTypeARM6432 = CPUTypeARM | CPUArchABI6432
	CPUTypePPC64   = CPUTypePowerPC | CPUArchABI64
)

const (
	CPUSubtypeARM_V6  = 6
	CPUSubtypeARM_V7  = 9
	CPUSubtypeARM_V7S = 11
	CPUSubtypeARM_V7K = 12
	CPUSubtypeARM_V8  = 13

	CPUSubtypeARM64_ALL = 0
	CPUSubtypeARM64_V8  = 1
	CPUSubtypeARM64E    = 2

	CPUSubtypeX86All   = 3
	CPUSubtypeX8664All = 3
)

const (
	FATMagic  uint32 = 0xcafebabe
	FATCigam  uint32 = 0xbebafeca
	MHMagic   uint32 = 0xfeedface
	MHCigam   uint32 = 0xcefaedfe
	MHMagic64 uint32 = 0xfeedfacf
	MHCigam64 uint32 = 0xcffaedfe
)

const (
	MHObject     = 0x1
	MHExecute    = 0x2
	MHFVMLib     = 0x3
	MHCore       = 0x4
	MHPreload    = 0x5
	MHDylib      = 0x6
	MHDylinker   = 0x7
	MHBundle     = 0x8
	MHDylibStub  = 0x9
	MHDsym       = 0xa
	MHKextBundle = 0xb
)

const (
	LCSegment           = 0x00000001
	LCSymTab            = 0x00000002
	LCThread            = 0x00000004
	LCUnixThread        = 0x00000005
	LCDySymTab          = 0x0000000b
	LCLoadDylib         = 0x0000000c
	LCIDDylib           = 0x0000000d
	LCLoadDylinker      = 0x0000000e
	LCRPath             = 0x8000001c
	LCCodeSignature     = 0x0000001d
	LCSegmentSplitInfo  = 0x0000001e
	LCReexportDylib     = 0x8000001f
	LCLazyLoadDylib     = 0x00000020
	LCEncryptionInfo    = 0x00000021
	LCDyldInfo          = 0x00000022
	LCDyldInfoOnly      = 0x80000022
	LCVersionMinMacOSX  = 0x00000024
	LCVersionMinIPhone  = 0x00000025
	LCFunctionStarts    = 0x00000026
	LCMain              = 0x80000028
	LCDataInCode        = 0x00000029
	LCSourceVersion     = 0x0000002a
	LCEncryptionInfo64  = 0x0000002c
	LCVersionMinTvOS    = 0x0000002f
	LCVersionMinWatchOS = 0x00000030
	LCLoadWeakDylib     = 0x80000018
	LCSegment64         = 0x00000019
	LCUUID              = 0x0000001b
)

const (
	CSMagicRequirement             uint32 = 0xfade0c00
	CSMagicRequirements            uint32 = 0xfade0c01
	CSMagicCodeDirectory           uint32 = 0xfade0c02
	CSMagicEmbeddedSignature       uint32 = 0xfade0cc0
	CSMagicEmbeddedEntitlements    uint32 = 0xfade7171
	CSMagicEmbeddedDEREntitlements uint32 = 0xfade7172
	CSMagicBlobWrapper             uint32 = 0xfade0b01

	CSSlotCodeDirectory             = 0
	CSSlotInfoSlot                  = 1
	CSSlotRequirements              = 2
	CSSlotResourceDir               = 3
	CSSlotApplication               = 4
	CSSlotEntitlements              = 5
	CSSlotDEREntitlements           = 7
	CSSlotAlternateCodeDirectories  = 0x1000
	CSSlotAlternateCodeDirectoryMax = 5
	CSSlotSignatureSlot             = 0x10000

	CSHashTypeSHA1   = 1
	CSHashTypeSHA256 = 2

	CSSL1Len   = 20
	CSSL256Len = 32

	CSSupportsScatter     = 0x20100
	CSSupportsTeamID      = 0x20200
	CSSupportsCodeLimit64 = 0x20300
	CSSupportsExecSeg     = 0x20400

	CSExecSegMainBinary    uint64 = 0x1
	CSExecSegAllowUnsigned uint64 = 0x10

	CSSecCodesignatureAdhoc uint32 = 0x0002
)

const (
	ReqOpFalse              = 0
	ReqOpTrue               = 1
	ReqOpIdent              = 2
	ReqOpAppleAnchor        = 3
	ReqOpAnchorHash         = 4
	ReqOpAnd                = 6
	ReqOpCertField          = 11
	ReqOpCertGeneric        = 14
	ReqOpAppleGenericAnchor = 15

	ReqMatchExists = 0
	ReqMatchEqual  = 1

	SecDesignatedRequirementType = 3
)

type FATHeader struct {
	Magic    uint32
	NFatArch uint32
}

type FATArch struct {
	CPUType    int32
	CPUSubtype int32
	Offset     uint32
	Size       uint32
	Align      uint32
}

type MachHeader struct {
	Magic      uint32
	CPUType    int32
	CPUSubtype int32
	FileType   uint32
	NCmds      uint32
	SizeOfCmds uint32
	Flags      uint32
}

type MachHeader64 struct {
	Magic      uint32
	CPUType    int32
	CPUSubtype int32
	FileType   uint32
	NCmds      uint32
	SizeOfCmds uint32
	Flags      uint32
	Reserved   uint32
}

type LoadCommand struct {
	Cmd     uint32
	CmdSize uint32
}

type SegmentCommand struct {
	Cmd      uint32
	CmdSize  uint32
	SegName  [16]byte
	VMAddr   uint32
	VMSize   uint32
	FileOff  uint32
	FileSize uint32
	MaxProt  int32
	InitProt int32
	NSects   uint32
	Flags    uint32
}

type SegmentCommand64 struct {
	Cmd      uint32
	CmdSize  uint32
	SegName  [16]byte
	VMAddr   uint64
	VMSize   uint64
	FileOff  uint64
	FileSize uint64
	MaxProt  int32
	InitProt int32
	NSects   uint32
	Flags    uint32
}

type Section32 struct {
	SectName  [16]byte
	SegName   [16]byte
	Addr      uint32
	Size      uint32
	Offset    uint32
	Align     uint32
	RelOff    uint32
	NReloc    uint32
	Flags     uint32
	Reserved1 uint32
	Reserved2 uint32
}

type Section64 struct {
	SectName  [16]byte
	SegName   [16]byte
	Addr      uint64
	Size      uint64
	Offset    uint32
	Align     uint32
	RelOff    uint32
	NReloc    uint32
	Flags     uint32
	Reserved1 uint32
	Reserved2 uint32
	Reserved3 uint32
}

type CodeSignatureCmd struct {
	Cmd      uint32
	CmdSize  uint32
	DataOff  uint32
	DataSize uint32
}

type EncryptionInfoCmd struct {
	Cmd       uint32
	CmdSize   uint32
	CryptOff  uint32
	CryptSize uint32
	CryptID   uint32
}

type EncryptionInfoCmd64 struct {
	Cmd       uint32
	CmdSize   uint32
	CryptOff  uint32
	CryptSize uint32
	CryptID   uint32
	Pad       uint32
}

type DylibCmd struct {
	Cmd                  uint32
	CmdSize              uint32
	NameOffset           uint32
	Timestamp            uint32
	CurrentVersion       uint32
	CompatibilityVersion uint32
}

type CSSuperBlob struct {
	Magic  uint32
	Length uint32
	Count  uint32
}

type CSBlobIndex struct {
	Type   uint32
	Offset uint32
}

type CSCodeDirectory struct {
	Magic         uint32
	Length        uint32
	Version       uint32
	Flags         uint32
	HashOffset    uint32
	IdentOffset   uint32
	NSpecialSlots uint32
	NCodeSlots    uint32
	CodeLimit     uint32
	HashSize      uint8
	HashType      uint8
	Spare1        uint8
	PageSize      uint8
	Spare2        uint32
	// Version >= 0x20100
	ScatterOffset uint32
	// Version >= 0x20200
	TeamOffset uint32
	// Version >= 0x20300
	Spare3      uint32
	CodeLimit64 uint64
	// Version >= 0x20400
	ExecSegBase  uint64
	ExecSegLimit uint64
	ExecSegFlags uint64
}

type archInfo struct {
	name string
}

func GetArchName(cpuType, cpuSubtype int32) string {
	switch cpuType {
	case CPUTypeARM:
		switch cpuSubtype {
		case CPUSubtypeARM_V6:
			return "armv6"
		case CPUSubtypeARM_V7:
			return "armv7"
		case CPUSubtypeARM_V7S:
			return "armv7s"
		case CPUSubtypeARM_V7K:
			return "armv7k"
		case CPUSubtypeARM_V8:
			return "armv8"
		}
	case CPUTypeARM64:
		switch cpuSubtype {
		case CPUSubtypeARM64_ALL:
			return "arm64"
		case CPUSubtypeARM64_V8:
			return "arm64v8"
		case CPUSubtypeARM64E:
			return "arm64e"
		}
	case CPUTypeARM6432:
		switch cpuSubtype {
		case CPUSubtypeARM64_ALL:
			return "arm64_32"
		case CPUSubtypeARM64_V8:
			return "arm64e_32"
		}
	case CPUTypeX86:
		return "x86_32"
	case CPUTypeX86_64:
		return "x86_64"
	}
	return "unknown"
}

func GetFileTypeName(fileType uint32) string {
	switch fileType {
	case MHObject:
		return "MH_OBJECT"
	case MHExecute:
		return "MH_EXECUTE"
	case MHFVMLib:
		return "MH_FVMLIB"
	case MHCore:
		return "MH_CORE"
	case MHPreload:
		return "MH_PRELOAD"
	case MHDylib:
		return "MH_DYLIB"
	case MHDylinker:
		return "MH_DYLINKER"
	case MHBundle:
		return "MH_BUNDLE"
	case MHDylibStub:
		return "MH_DYLIB_STUB"
	case MHDsym:
		return "MH_DSYM"
	case MHKextBundle:
		return "MH_KEXT_BUNDLE"
	}
	return "MH_UNKNOWN"
}
