package macho

import (
	"bytes"
	"crypto/sha1" //nolint:gosec
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/forgiverina/askua/pkg/cert"
	"github.com/forgiverina/askua/pkg/logger"
	"howett.net/plist"
)

type MachO struct {
	path   string
	data   []byte
	arches []*ArchO

	csRealloced bool
}

func Open(path string) (*MachO, error) {
	m := &MachO{path: path}
	if err := m.open(path); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *MachO) open(path string) error {
	m.close()

	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		if err2 := os.Chmod(path, 0755); err2 == nil {
			f, err = os.OpenFile(path, os.O_RDWR, 0)
		}
		if err != nil {
			return fmt.Errorf("open %s: %w", path, err)
		}
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return err
	}
	size := fi.Size()
	if size == 0 {
		return fmt.Errorf("empty file: %s", path)
	}

	data, err := mmapFile(f, int(size))
	if err != nil {
		return fmt.Errorf("mmap %s: %w", path, err)
	}
	m.data = data

	if len(data) < 4 {
		return fmt.Errorf("file too small: %s", path)
	}
	magic := binary.BigEndian.Uint32(data[:4])
	switch magic {
	case FATMagic, FATCigam:
		if err := m.parseFat(magic == FATMagic); err != nil {
			return err
		}
	case MHMagic, MHCigam, MHMagic64, MHCigam64:
		arch := &ArchO{}
		if err := arch.Init(data); err != nil {
			return fmt.Errorf("parse mach-o: %w", err)
		}
		m.arches = append(m.arches, arch)
	default:
		return fmt.Errorf("unknown magic 0x%08x in %s", magic, path)
	}

	return nil
}

func (m *MachO) parseFat(nativeEndian bool) error {
	read32 := func(b []byte) uint32 {
		v := binary.BigEndian.Uint32(b)
		if !nativeEndian {
			v = swapU32(v)
		}
		return v
	}

	if len(m.data) < 8 {
		return fmt.Errorf("fat header truncated")
	}
	nArch := int(read32(m.data[4:8]))
	for i := 0; i < nArch; i++ {
		base := 8 + i*20
		if base+20 > len(m.data) {
			return fmt.Errorf("fat header truncated at arch %d", i)
		}
		offset := read32(m.data[base+8:])
		size := read32(m.data[base+12:])
		end := int(offset) + int(size)
		if end > len(m.data) {
			return fmt.Errorf("fat arch %d slice out of bounds", i)
		}
		arch := &ArchO{}
		if err := arch.Init(m.data[offset:end]); err != nil {
			return fmt.Errorf("parse fat arch %d: %w", i, err)
		}
		m.arches = append(m.arches, arch)
	}
	return nil
}

func (m *MachO) close() error {
	if m.data == nil {
		return nil
	}
	msyncFile(m.data)
	err := unmapFile(m.data)
	m.data = nil
	m.arches = nil
	return err
}

func (m *MachO) Close() error {
	return m.close()
}

func (m *MachO) GetSigningCert() *x509.Certificate {
	for _, a := range m.arches {
		if c := a.GetSigningCert(); c != nil {
			return c
		}
	}
	return nil
}

func (m *MachO) PrintInfo() {
	for _, a := range m.arches {
		a.PrintInfo()
	}
}

func (m *MachO) CheckSignature() bool {
	for _, a := range m.arches {
		if !a.IsSigned() {
			return false
		}
	}
	return true
}

func (m *MachO) Sign(asset *cert.Asset, force bool, bundleID, infoSHA1, infoSHA256, codeResData string) error {
	if m.data == nil || len(m.arches) == 0 {
		return fmt.Errorf("binary not loaded")
	}
	defer m.close() //nolint:errcheck — close() is idempotent; final return propagates sign errors

	if len(m.arches) == 1 {
		a := m.arches[0]
		bid, s1, s256 := archSignIDs(a, m.path, bundleID, infoSHA1, infoSHA256)
		if err := a.Sign(asset, force, bid, s1, s256, codeResData); err != nil {
			if !a.enoughSpace && !m.csRealloced {
				m.csRealloced = true
				if rerr := m.reallocAndReopen(); rerr != nil {
					return fmt.Errorf("realloc code sign space arch 0: %w", rerr)
				}
				return m.Sign(asset, force, bundleID, infoSHA1, infoSHA256, codeResData)
			}
			return fmt.Errorf("sign arch 0: %w", err)
		}
		return nil
	}

	type result struct {
		err         error
		needRealloc bool
	}
	results := make([]result, len(m.arches))
	var wg sync.WaitGroup
	wg.Add(len(m.arches))
	for i, a := range m.arches {
		go func(i int, a *ArchO) {
			defer wg.Done()
			bid, s1, s256 := archSignIDs(a, m.path, bundleID, infoSHA1, infoSHA256)
			err := a.Sign(asset, force, bid, s1, s256, codeResData)
			results[i] = result{err: err, needRealloc: !a.enoughSpace}
		}(i, a)
	}
	wg.Wait()

	for i, r := range results {
		if r.err != nil {
			if r.needRealloc && !m.csRealloced {
				m.csRealloced = true
				if rerr := m.reallocAndReopen(); rerr != nil {
					return fmt.Errorf("realloc code sign space arch %d: %w", i, rerr)
				}
				return m.Sign(asset, force, bundleID, infoSHA1, infoSHA256, codeResData)
			}
			return fmt.Errorf("sign arch %d: %w", i, r.err)
		}
	}
	return nil
}

func archSignIDs(a *ArchO, filePath, bundleID, infoSHA1, infoSHA256 string) (bid, s1, s256 string) {
	bid, s1, s256 = bundleID, infoSHA1, infoSHA256
	if bid == "" {
		if a.infoPlist != "" {
			bid = extractPlistString([]byte(a.infoPlist), "CFBundleIdentifier")
		}
		if bid == "" {
			bid = filepath.Base(filePath)
		}
	}
	if s1 == "" || s256 == "" {
		if a.infoPlist == "" {
			s1 = string(make([]byte, 20))
			s256 = string(make([]byte, 32))
		} else {
			h1 := sha1.Sum([]byte(a.infoPlist)) //nolint:gosec
			h256 := sha256.Sum256([]byte(a.infoPlist))
			s1 = string(h1[:])
			s256 = string(h256[:])
		}
	}
	return
}

func (m *MachO) InjectDylib(weak bool, path string) error {
	logger.Warnf("- InjectDylib: %s %s...\n", path, map[bool]string{true: "(weak)", false: ""}[weak])
	for _, a := range m.arches {
		if err := a.InjectDylib(weak, path); err != nil {
			return err
		}
	}
	logger.Warn("- Success!\n")
	return nil
}

func (m *MachO) RemoveDylibs(dylibs map[string]struct{}) {
	for _, a := range m.arches {
		a.RemoveDylibs(dylibs)
	}
}

func (m *MachO) reallocAndReopen() error {
	logger.Warn("- Realloc CodeSignature space...\n")

	type archResult struct {
		size    uint32
		tmpPath string
	}
	results := make([]archResult, len(m.arches))

	for i, a := range m.arches {
		tmp := fmt.Sprintf("%s.archo.%d", m.path, i)
		size, err := a.ReallocCodeSignSpace(tmp)
		if err != nil || size == 0 {
			return fmt.Errorf("realloc arch %d: %w", i, err)
		}
		results[i] = archResult{size: size, tmpPath: tmp}
	}
	logger.Warn("- Success!\n")

	if len(m.arches) == 1 {
		m.close()
		_ = os.Remove(m.path)
		if err := os.Rename(results[0].tmpPath, m.path); err != nil {
			return err
		}
		return m.open(m.path)
	}

	const align = uint32(16384)
	nArch := len(results)
	fatHdrSize := uint32(8 + nArch*20)
	pad1 := align - fatHdrSize%align
	offset := fatHdrSize + pad1

	type archOffset struct {
		offset, size uint32
	}
	offsets := make([]archOffset, nArch)
	for i, r := range results {
		offsets[i] = archOffset{offset, r.size}
		padded := r.size + (align - r.size%align)
		offset += padded
	}

	type archCPU struct{ cpuType, cpuSubtype uint32 }
	cpuInfos := make([]archCPU, nArch)
	for i := 0; i < nArch; i++ {
		base := 8 + i*20
		cpuInfos[i] = archCPU{
			cpuType:    binary.BigEndian.Uint32(m.data[base:]),
			cpuSubtype: binary.BigEndian.Uint32(m.data[base+4:]),
		}
	}

	fatHeader := make([]byte, fatHdrSize)
	binary.BigEndian.PutUint32(fatHeader[0:], FATMagic)
	binary.BigEndian.PutUint32(fatHeader[4:], uint32(nArch))
	for i, ao := range offsets {
		base := 8 + i*20
		binary.BigEndian.PutUint32(fatHeader[base:], cpuInfos[i].cpuType)
		binary.BigEndian.PutUint32(fatHeader[base+4:], cpuInfos[i].cpuSubtype)
		binary.BigEndian.PutUint32(fatHeader[base+8:], ao.offset)
		binary.BigEndian.PutUint32(fatHeader[base+12:], ao.size)
		binary.BigEndian.PutUint32(fatHeader[base+16:], 14) // align = 2^14
	}

	tmpFat := m.path + ".fato"
	out, err := os.Create(tmpFat)
	if err != nil {
		return err
	}

	if _, err := out.Write(fatHeader); err != nil {
		out.Close()
		return err
	}
	if _, err := out.Write(bytes.Repeat([]byte{0}, int(pad1))); err != nil {
		out.Close()
		return err
	}

	for _, r := range results {
		archData, err := os.ReadFile(r.tmpPath)
		if err != nil {
			out.Close()
			return err
		}
		_ = os.Remove(r.tmpPath)
		if _, err := out.Write(archData); err != nil {
			out.Close()
			return err
		}
		archPad := align - uint32(len(archData))%align
		if _, err := out.Write(bytes.Repeat([]byte{0}, int(archPad))); err != nil {
			out.Close()
			return err
		}
	}
	out.Close()

	m.close()
	_ = os.Remove(m.path)
	if err := os.Rename(tmpFat, m.path); err != nil {
		return err
	}
	return m.open(m.path)
}

func extractPlistString(data []byte, key string) string {
	var m map[string]interface{}
	if _, err := plist.Unmarshal(data, &m); err != nil {
		return ""
	}
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
