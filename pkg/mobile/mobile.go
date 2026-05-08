package mobile

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/forgiverina/askua/pkg/archive"
	"github.com/forgiverina/askua/pkg/bundle"
	"github.com/forgiverina/askua/pkg/cert"
	"github.com/forgiverina/askua/pkg/logger"
	"github.com/forgiverina/askua/pkg/macho"
	"github.com/forgiverina/askua/pkg/metadata"
)

type SignOptions struct {
	CertPath string // path to .pem or .cer certificate file (empty for adhoc/p12)
	KeyPath  string // path to .pem or .p12 private key file
	ProvPath string // path to .mobileprovision file (empty for ad-hoc)
	Password string // passphrase for p12 or encrypted key

	BundleID      string // override CFBundleIdentifier (empty = keep original)
	BundleName    string // override CFBundleDisplayName
	BundleVersion string // override CFBundleVersion

	Adhoc       bool   // ad-hoc signature (no cert/prov required)
	ForceResign bool   // re-sign even if signature is fresh
	WeakDylib   bool   // inject dylibs as LC_LOAD_WEAK_DYLIB
	ZipLevel    int    // output IPA compression level 0–9 (0 = store)
	TempDir     string // working directory for extracted files (defaults to os.TempDir)

	OutputPath  string // destination IPA path; if empty the input is signed in place
	MetadataDir string // if non-empty, extract metadata.json + icon here

	EnableDocuments  bool   // set UISupportsDocumentBrowser + UIFileSharingEnabled
	RemoveExtensions bool   // strip PlugIns/Extensions
	RemoveWatchApp   bool   // strip embedded Watch app
	MinVersion       string // override MinimumOSVersion
}

type SignResult struct {
	Success bool
	Error   string
	Elapsed int64
}

func Sign(inputPath string, opts *SignOptions) *SignResult {
	start := time.Now()
	err := sign(inputPath, opts)
	elapsed := time.Since(start).Milliseconds()
	if err != nil {
		return &SignResult{Success: false, Error: err.Error(), Elapsed: elapsed}
	}
	return &SignResult{Success: true, Elapsed: elapsed}
}

func CheckSignature(path string) bool {
	m, err := macho.Open(path)
	if err != nil {
		return false
	}
	defer m.Close()
	return m.CheckSignature()
}

func ExtractMetadata(appFolder, outputDir string) string {
	if err := metadata.Extract(appFolder, outputDir, ""); err != nil {
		return err.Error()
	}
	return ""
}

func SetLogLevel(level int) {
	switch level {
	case 0:
		logger.SetLevel(logger.LevelNone)
	case 2:
		logger.SetLevel(logger.LevelDebug)
	default:
		logger.SetLevel(logger.LevelInfo)
	}
}

func sign(inputPath string, opts *SignOptions) error {
	if opts == nil {
		return fmt.Errorf("opts must not be nil")
	}

	absPath, err := filepath.Abs(inputPath)
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}
	if _, err := os.Stat(absPath); err != nil {
		return fmt.Errorf("path not found: %s", absPath)
	}

	if opts.ZipLevel < 0 || opts.ZipLevel > 9 {
		return fmt.Errorf("ZipLevel must be 0–9")
	}

	tmpDir := opts.TempDir
	if tmpDir == "" {
		tmpDir = os.TempDir()
	}

	isZip := archive.IsZipFile(absPath)
	isDir := func() bool {
		fi, err := os.Stat(absPath)
		return err == nil && fi.IsDir()
	}()

	if !isZip && !isDir {
		return signMachO(absPath, opts)
	}

	if len(opts.ProvPath) == 0 && !opts.Adhoc {
		return fmt.Errorf("ProvPath or Adhoc=true is required for bundle signing")
	}

	a := &cert.Asset{}
	if err := a.Init(
		opts.CertPath, opts.KeyPath, opts.ProvPath, "",
		opts.Password, opts.Adhoc, false, false,
	); err != nil {
		return fmt.Errorf("load signing assets: %w", err)
	}

	sigFolder := absPath
	tmpFolder := ""
	if isZip {
		tmpFolder = filepath.Join(tmpDir, fmt.Sprintf("askua_folder_%d", time.Now().UnixMicro()))
		if err := archive.Extract(absPath, tmpFolder); err != nil {
			return fmt.Errorf("extract IPA: %w", err)
		}
		sigFolder = tmpFolder
		opts.ForceResign = true
	}
	defer func() {
		if tmpFolder != "" {
			_ = os.RemoveAll(tmpFolder)
		}
	}()

	b := &bundle.Bundle{
		EnableDocuments:  opts.EnableDocuments,
		MinVersion:       opts.MinVersion,
		RemoveExtensions: opts.RemoveExtensions,
		RemoveWatchApp:   opts.RemoveWatchApp,
	}
	if err := b.SignFolder(
		[]*cert.Asset{a}, sigFolder,
		opts.BundleID, opts.BundleVersion, opts.BundleName,
		nil, nil,
		opts.ForceResign, opts.WeakDylib, !isZip, false,
	); err != nil {
		return fmt.Errorf("sign bundle: %w", err)
	}

	if opts.OutputPath != "" {
		appFolder, aerr := bundle.FindAppFolder(sigFolder)
		if aerr != nil {
			return fmt.Errorf("find app folder: %w", aerr)
		}
		baseFolder := appFolder
		if idx := lastIndex(appFolder, "Payload"); idx >= 1 {
			baseFolder = appFolder[:idx-1]
		}
		if err := archive.Archive(baseFolder, opts.OutputPath, opts.ZipLevel); err != nil {
			return fmt.Errorf("archive IPA: %w", err)
		}

		if opts.MetadataDir != "" {
			_ = metadata.Extract(appFolder, opts.MetadataDir, opts.OutputPath)
		}
	} else if opts.MetadataDir != "" {
		if appFolder, aerr := bundle.FindAppFolder(sigFolder); aerr == nil {
			_ = metadata.Extract(appFolder, opts.MetadataDir, "")
		}
	}

	return nil
}

func signMachO(path string, opts *SignOptions) error {
	m, err := macho.Open(path)
	if err != nil {
		return fmt.Errorf("open Mach-O: %w", err)
	}

	a := &cert.Asset{}
	prov := opts.ProvPath
	if err := a.Init(
		opts.CertPath, opts.KeyPath, prov, "",
		opts.Password, opts.Adhoc, false, true,
	); err != nil {
		return fmt.Errorf("load signing assets: %w", err)
	}

	if err := m.Sign(a, opts.ForceResign, opts.BundleID, "", "", ""); err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	return nil
}

func lastIndex(s, substr string) int {
	for i := len(s) - len(substr); i >= 0; i-- {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
