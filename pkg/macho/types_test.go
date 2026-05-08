package macho_test

import (
	"testing"

	"github.com/forgiverina/askua/pkg/macho"
)

func TestGetArchName(t *testing.T) {
	cases := []struct {
		cpuType, cpuSubtype int32
		want                string
	}{
		{macho.CPUTypeARM64, macho.CPUSubtypeARM64_ALL, "arm64"},
		{macho.CPUTypeARM64, macho.CPUSubtypeARM64E, "arm64e"},
		{macho.CPUTypeARM, macho.CPUSubtypeARM_V7, "armv7"},
		{macho.CPUTypeARM, macho.CPUSubtypeARM_V7S, "armv7s"},
		{macho.CPUTypeX86_64, macho.CPUSubtypeX8664All, "x86_64"},
		{99, 0, "unknown"},
	}
	for _, c := range cases {
		got := macho.GetArchName(c.cpuType, c.cpuSubtype)
		if got != c.want {
			t.Errorf("GetArchName(%d,%d) = %q, want %q", c.cpuType, c.cpuSubtype, got, c.want)
		}
	}
}

func TestGetFileTypeName(t *testing.T) {
	cases := []struct {
		ft   uint32
		want string
	}{
		{macho.MHExecute, "MH_EXECUTE"},
		{macho.MHDylib, "MH_DYLIB"},
		{macho.MHBundle, "MH_BUNDLE"},
		{0xdeadbeef, "MH_UNKNOWN"},
	}
	for _, c := range cases {
		got := macho.GetFileTypeName(c.ft)
		if got != c.want {
			t.Errorf("GetFileTypeName(0x%x) = %q, want %q", c.ft, got, c.want)
		}
	}
}
