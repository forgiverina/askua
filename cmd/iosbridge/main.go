package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"unsafe"

	"github.com/forgiverina/askua/pkg/mobile"
)

//export AskuaSign
func AskuaSign(ipa, p12, prov, password, bundleID, out, tmp *C.char) *C.char {
	mobile.SetLogLevel(0)
	r := mobile.Sign(C.GoString(ipa), &mobile.SignOptions{
		KeyPath:     C.GoString(p12),
		ProvPath:    C.GoString(prov),
		Password:    C.GoString(password),
		BundleID:    C.GoString(bundleID),
		OutputPath:  C.GoString(out),
		TempDir:     C.GoString(tmp),
		ForceResign: true,
	})
	if r.Success {
		return nil
	}
	return C.CString(r.Error)
}

//export AskuaFree
func AskuaFree(p *C.char) { C.free(unsafe.Pointer(p)) }

func main() {}
