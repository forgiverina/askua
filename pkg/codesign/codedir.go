package codesign

import (
	"bytes"
	"crypto/sha1" //nolint:gosec
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"runtime"
	"sync"

	"github.com/forgiverina/askua/pkg/logger"
)

type CDParams struct {
	CodeBase          []byte
	ExistingCodeSlots []byte
	ExecSegLimit      uint64
	ExecSegFlags      uint64
	BundleID          string
	TeamID            string
	InfoPlistSHA1     []byte
	InfoPlistSHA256   []byte
	ReqSlotSHA1       []byte
	ReqSlotSHA256     []byte
	CodeResSHA1       []byte
	CodeResSHA256     []byte
	EntSlotSHA1       []byte
	EntSlotSHA256     []byte
	DEREntSlotSHA1    []byte
	DEREntSlotSHA256  []byte
	IsExecute         bool
	IsAdhoc           bool
}

const (
	cdVersion    = 0x20400
	pageSize     = uint32(4096)
	pageSizeLog2 = uint8(12)
)

func ComputePageHashes(codeBase []byte) (sha1Slots, sha256Slots []byte) {
	const pageSize = 4096
	codeLen := len(codeBase)
	if codeLen == 0 {
		return nil, nil
	}
	nPages := codeLen / pageSize
	remain := codeLen % pageSize
	nSlots := nPages
	if remain > 0 {
		nSlots++
	}

	sha1Slots = make([]byte, nSlots*20)
	sha256Slots = make([]byte, nSlots*32)

	numWorkers := runtime.GOMAXPROCS(0)
	if numWorkers > nSlots {
		numWorkers = nSlots
	}

	jobs := make(chan int, nSlots)
	for i := 0; i < nSlots; i++ {
		jobs <- i
	}
	close(jobs)

	var wg sync.WaitGroup
	wg.Add(numWorkers)
	for w := 0; w < numWorkers; w++ {
		go func() {
			defer wg.Done()
			for i := range jobs {
				var page []byte
				if i < nPages {
					page = codeBase[i*pageSize : (i+1)*pageSize]
				} else {
					page = codeBase[nPages*pageSize:]
				}
				h1 := sha1.Sum(page) //nolint:gosec
				h256 := sha256.Sum256(page)
				copy(sha1Slots[i*20:], h1[:])
				copy(sha256Slots[i*32:], h256[:])
			}
		}()
	}
	wg.Wait()
	return
}

func BuildCodeDirectory(alternate bool, p CDParams) ([]byte, error) {
	if len(p.CodeBase) == 0 || p.BundleID == "" {
		return nil, fmt.Errorf("code base and bundle ID are required")
	}
	if p.TeamID == "" && !p.IsAdhoc {
		return nil, fmt.Errorf("team ID required for non-adhoc signing")
	}

	hashSize := uint8(20)
	hashType := uint8(1) // SHA1
	if alternate {
		hashSize = 32
		hashType = 2 // SHA256
	}

	chooseHash := func(sha1h, sha256h []byte) []byte {
		if alternate {
			return sha256h
		}
		return sha1h
	}

	empty := make([]byte, hashSize)

	// Special slots stored most-negative first: [-7]=DEREntitlements … [-1]=InfoPlist.
	var specials [][]byte

	if p.IsExecute {
		derHash := chooseHash(p.DEREntSlotSHA1, p.DEREntSlotSHA256)
		if len(derHash) == 0 {
			derHash = empty
		}
		specials = append(specials, derHash) // slot -7 (DER entitlements)
		specials = append(specials, empty)   // slot -6 unused
	}
	entHash := chooseHash(p.EntSlotSHA1, p.EntSlotSHA256)
	if len(entHash) == 0 {
		entHash = empty
	}
	specials = append(specials, entHash) // slot -5 (entitlements)
	specials = append(specials, empty)   // slot -4 unused (app-specific)
	codeResHash := chooseHash(p.CodeResSHA1, p.CodeResSHA256)
	if len(codeResHash) == 0 {
		codeResHash = empty
	}
	specials = append(specials, codeResHash) // slot -3 (code resources)
	reqHash := chooseHash(p.ReqSlotSHA1, p.ReqSlotSHA256)
	if len(reqHash) == 0 {
		reqHash = empty
	}
	specials = append(specials, reqHash) // slot -2 (requirements)
	infoHash := chooseHash(p.InfoPlistSHA1, p.InfoPlistSHA256)
	if len(infoHash) == 0 {
		infoHash = empty
	}
	specials = append(specials, infoHash) // slot -1 (info plist)

	for len(specials) > 0 && bytes.Equal(specials[0], empty) {
		specials = specials[1:]
	}

	nSpecial := uint32(len(specials))
	codeLen := uint32(len(p.CodeBase))
	nPages := codeLen / pageSize
	remain := codeLen % pageSize
	nCodeSlots := nPages
	if remain > 0 {
		nCodeSlots++
	}

	hdrLen := uint32(44 + 4 + 4 + 4 + 8 + 8 + 8 + 8) // fixed fields through execSegFlags (v0x20400)

	bundleIDBytes := append([]byte(p.BundleID), 0)
	var teamIDBytes []byte
	if p.TeamID != "" {
		teamIDBytes = append([]byte(p.TeamID), 0)
	}

	identOffset := hdrLen
	hashOffset := identOffset + uint32(len(bundleIDBytes))
	if len(teamIDBytes) > 0 {
		hashOffset += uint32(len(teamIDBytes))
	}
	hashOffset += nSpecial * uint32(hashSize)

	var flags uint32
	if p.IsAdhoc {
		flags = 0x0002
	}

	var hdr bytes.Buffer
	be := binary.BigEndian
	write32 := func(v uint32) { var b [4]byte; be.PutUint32(b[:], v); hdr.Write(b[:]) }
	write64 := func(v uint64) { var b [8]byte; be.PutUint64(b[:], v); hdr.Write(b[:]) }
	write8 := func(v uint8) { hdr.WriteByte(v) }

	write32(0xfade0c02) // CSMAGIC_CODEDIRECTORY
	write32(0)          // length placeholder
	write32(cdVersion)
	write32(flags)
	write32(hashOffset)
	write32(identOffset)
	write32(nSpecial)
	write32(nCodeSlots)
	write32(codeLen)
	write8(hashSize)
	write8(hashType)
	write8(0) // spare1
	write8(pageSizeLog2)
	write32(0) // spare2

	write32(0) // scatterOffset (unused)

	teamOff := uint32(0)
	if len(teamIDBytes) > 0 {
		teamOff = identOffset + uint32(len(bundleIDBytes))
	}
	write32(teamOff)
	write32(0)               // spare3
	write64(uint64(codeLen)) // codeLimit64
	write64(0)               // execSegBase
	write64(p.ExecSegLimit)
	write64(p.ExecSegFlags)

	hdr.Write(bundleIDBytes)
	if len(teamIDBytes) > 0 {
		hdr.Write(teamIDBytes)
	}

	for _, s := range specials {
		hdr.Write(s)
	}

	if len(p.ExistingCodeSlots) == int(nCodeSlots*uint32(hashSize)) {
		hdr.Write(p.ExistingCodeSlots)
	} else {
		hash := func(data []byte) []byte {
			if alternate {
				h := sha256.Sum256(data)
				return h[:]
			}
			h := sha1.Sum(data) //nolint:gosec
			return h[:]
		}
		for i := uint32(0); i < nPages; i++ {
			hdr.Write(hash(p.CodeBase[i*pageSize : (i+1)*pageSize]))
		}
		if remain > 0 {
			hdr.Write(hash(p.CodeBase[nPages*pageSize:]))
		}
	}

	result := hdr.Bytes()
	be.PutUint32(result[4:], uint32(len(result)))
	return result, nil
}

func ExtractCodeSlots(sig []byte) (sha1Slots, sha256Slots []byte) {
	if len(sig) < 12 {
		return nil, nil
	}
	magic := binary.BigEndian.Uint32(sig[:4])
	if magic != 0xfade0cc0 {
		return nil, nil
	}
	count := binary.BigEndian.Uint32(sig[8:12])

	for i := uint32(0); i < count; i++ {
		base := 12 + i*8
		if int(base)+8 > len(sig) {
			break
		}
		slotType := binary.BigEndian.Uint32(sig[base:])
		offset := binary.BigEndian.Uint32(sig[base+4:])
		if int(offset)+8 > len(sig) {
			continue
		}
		slotMagic := binary.BigEndian.Uint32(sig[offset:])
		if slotMagic != 0xfade0c02 {
			continue
		}
		slotLen := binary.BigEndian.Uint32(sig[offset+4:])
		if int(offset)+int(slotLen) > len(sig) {
			continue
		}
		slotData := sig[offset : offset+slotLen]
		if len(slotData) < 44 {
			continue
		}
		hashOffset := binary.BigEndian.Uint32(slotData[16:])
		nCodeSlots := binary.BigEndian.Uint32(slotData[28:])
		hashSize := slotData[36]
		codeSlotEnd := hashOffset + nCodeSlots*uint32(hashSize)
		if int(codeSlotEnd) > len(slotData) {
			continue
		}
		codeSlotData := slotData[hashOffset : hashOffset+nCodeSlots*uint32(hashSize)]

		switch slotType {
		case 0: // CSSLOT_CODEDIRECTORY (SHA1)
			sha1Slots = codeSlotData
		case 0x1000: // CSSLOT_ALTERNATE_CODEDIRECTORIES (SHA256)
			sha256Slots = codeSlotData
		}
	}
	return
}

func ParseCodeSignature(sig []byte) {
	if len(sig) < 12 {
		return
	}
	magic := binary.BigEndian.Uint32(sig[:4])
	if magic != 0xfade0cc0 {
		return
	}
	total := binary.BigEndian.Uint32(sig[4:8])
	count := binary.BigEndian.Uint32(sig[8:12])
	logger.Printf("\n- CodeSignature Segment:\n")
	logger.Printf("\tmagic: \t\t0x%x\n", magic)
	logger.Printf("\tlength: \t%d\n", total)
	logger.Printf("\tslots: \t\t%d\n", count)
}

func AlignUp(v, align uint32) uint32 {
	if v%align == 0 {
		return v
	}
	return v + align - v%align
}
