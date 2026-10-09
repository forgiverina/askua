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
	CertPath string
	KeyPath  string
	ProvPath string
	Password string

	BundleID      string
	BundleName    string
	BundleVersion string

	Adhoc       bool
	ForceResign bool
	WeakDylib   bool
	ZipLevel    int
	TempDir     string

	OutputPath  string
	MetadataDir string

	EnableDocuments  bool
	RemoveExtensions bool
	RemoveWatchApp   bool
	MinVersion       string
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
	force := opts.ForceResign
	if isZip {
		tmpFolder := filepath.Join(tmpDir, fmt.Sprintf("askua_folder_%d", time.Now().UnixMicro()))
		defer os.RemoveAll(tmpFolder)
		if err := archive.Extract(absPath, tmpFolder); err != nil {
			return fmt.Errorf("extract IPA: %w", err)
		}
		sigFolder = tmpFolder
		force = true
	}

	b := &bundle.Bundle{
		BundleID:         opts.BundleID,
		BundleVersion:    opts.BundleVersion,
		DisplayName:      opts.BundleName,
		MinVersion:       opts.MinVersion,
		WeakInject:       opts.WeakDylib,
		Force:            force,
		EnableCache:      !isZip,
		EnableDocuments:  opts.EnableDocuments,
		RemoveExtensions: opts.RemoveExtensions,
		RemoveWatchApp:   opts.RemoveWatchApp,
	}
	if err := b.SignFolder([]*cert.Asset{a}, sigFolder); err != nil {
		return fmt.Errorf("sign bundle: %w", err)
	}

	appFolder, err := bundle.FindAppFolder(sigFolder)
	if err != nil {
		return fmt.Errorf("find app folder: %w", err)
	}

	if opts.OutputPath != "" {
		baseFolder, err := bundle.PayloadRoot(appFolder)
		if err != nil {
			return fmt.Errorf("archive IPA: %w", err)
		}
		if err := archive.Archive(baseFolder, opts.OutputPath, opts.ZipLevel); err != nil {
			return fmt.Errorf("archive IPA: %w", err)
		}
	}
	if opts.MetadataDir != "" {
		_ = metadata.Extract(appFolder, opts.MetadataDir, opts.OutputPath)
	}
	return nil
}

func signMachO(path string, opts *SignOptions) error {
	a := &cert.Asset{}
	if err := a.Init(
		opts.CertPath, opts.KeyPath, opts.ProvPath, "",
		opts.Password, opts.Adhoc, false, true,
	); err != nil {
		return fmt.Errorf("load signing assets: %w", err)
	}

	m, err := macho.Open(path)
	if err != nil {
		return fmt.Errorf("open Mach-O: %w", err)
	}
	defer m.Close()

	if err := m.Sign(a, opts.ForceResign, opts.BundleID, "", "", ""); err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	return nil
}
