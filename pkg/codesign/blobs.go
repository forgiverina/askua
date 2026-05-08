package codesign

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"howett.net/plist"
)

func BuildRequirements(bundleID, subjectCN string) []byte {
	var out bytes.Buffer
	w32 := func(v uint32) { var b [4]byte; binary.BigEndian.PutUint32(b[:], v); out.Write(b[:]) }

	if bundleID == "" || subjectCN == "" {
		w32(0xfade0c01) // CSMAGIC_REQUIREMENTS
		w32(12)
		w32(0) // count=0
		return out.Bytes()
	}

	// WWDR OID: 1.2.840.113635.100.6.2.1
	wwdrOID := []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x06, 0x02, 0x01}

	padStr := func(buf *bytes.Buffer, s string) {
		b := []byte(s)
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(b)))
		buf.Write(l[:])
		buf.Write(b)
		if pad := (4 - len(b)%4) % 4; pad > 0 {
			buf.Write(make([]byte, pad))
		}
	}
	padBytes := func(buf *bytes.Buffer, b []byte) {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(b)))
		buf.Write(l[:])
		buf.Write(b)
		if pad := (4 - len(b)%4) % 4; pad > 0 {
			buf.Write(make([]byte, pad))
		}
	}
	op := func(buf *bytes.Buffer, v uint32) {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], v)
		buf.Write(b[:])
	}

	var expr bytes.Buffer
	op(&expr, 1) // opTrue

	// opAnd( opIdent(bundleID), opAnd( opAppleGenericAnchor,
	//   opAnd( opCertField(leaf, "subject.CN", matchEqual, subjectCN),
	//          opCertGeneric(1, wwdrOID, matchExists) ) ) )
	op(&expr, 6) // kReqOpAnd
	op(&expr, 2) // kReqOpIdent
	padStr(&expr, bundleID)

	op(&expr, 6)  // kReqOpAnd
	op(&expr, 15) // kReqOpAppleGenericAnchor

	op(&expr, 6)  // kReqOpAnd
	op(&expr, 11) // kReqOpCertField
	op(&expr, 0)  // leaf certificate
	padStr(&expr, "subject.CN")
	op(&expr, 1) // kReqMatchEqual
	padStr(&expr, subjectCN)

	op(&expr, 14) // kReqOpCertGeneric
	op(&expr, 1)  // intermediate certificate (slot 1)
	padBytes(&expr, wwdrOID)
	op(&expr, 0) // kReqMatchExists

	innerLen := uint32(8) + uint32(expr.Len())
	outerLen := uint32(20) + innerLen

	w32(0xfade0c01) // CSMAGIC_REQUIREMENTS
	w32(outerLen)
	w32(1)          // count=1
	w32(3)          // kSecDesignatedRequirementType
	w32(20)         // offset to inner blob
	w32(0xfade0c00) // CSMAGIC_REQUIREMENT
	w32(innerLen)
	out.Write(expr.Bytes())

	return out.Bytes()
}

func BuildEntitlements(xmlData string) []byte {
	if xmlData == "" {
		return nil
	}
	var out bytes.Buffer
	binary.Write(&out, binary.BigEndian, uint32(0xfade7171))     //nolint:errcheck
	binary.Write(&out, binary.BigEndian, uint32(len(xmlData)+8)) //nolint:errcheck
	out.WriteString(xmlData)
	return out.Bytes()
}

func BuildDEREntitlements(xmlData string) ([]byte, error) {
	if xmlData == "" {
		return nil, nil
	}

	var parsed interface{}
	if _, err := plist.Unmarshal([]byte(xmlData), &parsed); err != nil {
		return nil, fmt.Errorf("parse entitlements plist: %w", err)
	}

	der, err := encodeDER(parsed)
	if err != nil {
		return nil, fmt.Errorf("DER encode entitlements: %w", err)
	}

	var out bytes.Buffer
	binary.Write(&out, binary.BigEndian, uint32(0xfade7172)) //nolint:errcheck
	binary.Write(&out, binary.BigEndian, uint32(len(der)+8)) //nolint:errcheck
	out.Write(der)
	return out.Bytes(), nil
}

func BuildSuperBlob(cdSlot1, reqSlot, entSlot, derSlot, cdSlot256, cmsSlot []byte) []byte {
	type blobEntry struct {
		slotType uint32
		data     []byte
	}
	var entries []blobEntry

	if len(cdSlot1) > 0 {
		entries = append(entries, blobEntry{0, cdSlot1})
	}
	if len(reqSlot) > 0 {
		entries = append(entries, blobEntry{2, reqSlot})
	}
	if len(entSlot) > 0 {
		entries = append(entries, blobEntry{5, entSlot})
	}
	if len(derSlot) > 0 {
		entries = append(entries, blobEntry{7, derSlot})
	}
	if len(cdSlot256) > 0 {
		entries = append(entries, blobEntry{0x1000, cdSlot256})
	}
	if len(cmsSlot) > 0 {
		entries = append(entries, blobEntry{0x10000, cmsSlot})
	}

	indexSize := uint32(len(entries)) * 8
	headerSize := 12 + indexSize

	totalLen := headerSize
	for _, e := range entries {
		totalLen += uint32(len(e.data))
	}

	var out bytes.Buffer
	w32 := func(v uint32) { var b [4]byte; binary.BigEndian.PutUint32(b[:], v); out.Write(b[:]) }

	w32(0xfade0cc0) // CSMAGIC_EMBEDDED_SIGNATURE
	w32(totalLen)
	w32(uint32(len(entries)))

	offset := headerSize
	for _, e := range entries {
		w32(e.slotType)
		w32(offset)
		offset += uint32(len(e.data))
	}

	for _, e := range entries {
		out.Write(e.data)
	}

	return out.Bytes()
}
