package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"howett.net/plist"

	"github.com/forgiverina/askua/pkg/archive"
	"github.com/forgiverina/askua/pkg/bundle"
	"github.com/forgiverina/askua/pkg/cert"
	"github.com/forgiverina/askua/pkg/certcheck"
	"github.com/forgiverina/askua/pkg/logger"
	"github.com/forgiverina/askua/pkg/macho"
	"github.com/forgiverina/askua/pkg/metadata"
)

type runOpts struct {
	debug, force, verbose, adhoc, sha256Only, weakInject bool
	install, checkSig, quiet, removeProvision            bool
	enableDocs, removeExts, removeWatch, removeUISD      bool

	certFile, pkeyFile, password        string
	provFiles                           []string
	bundleID, bundleName, bundleVer     string
	entitleFile, outputFile, tempFolder string
	metadataDir, minVersion             string
	installerPath                       string

	zipLevel   int
	dylibFiles []string
	rmDylibs   []string
}

func run(path string, o runOpts) error {
	start := time.Now()

	switch {
	case o.debug, o.verbose:
		logger.SetLevel(logger.LevelDebug)
	case o.quiet:
		logger.SetLevel(logger.LevelNone)
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}
	if _, err := os.Stat(absPath); err != nil {
		return fmt.Errorf("path not found: %s", absPath)
	}

	if o.zipLevel < 0 || o.zipLevel > 9 {
		return fmt.Errorf("invalid zip level %d (must be 0–9)", o.zipLevel)
	}

	if logger.IsDebug() {
		_ = os.MkdirAll(".askua_debug", 0755)
		logger.Debugf("- Path:\t%s\n", absPath)
	}

	for i, dylibPath := range o.dylibFiles {
		abs, err := filepath.Abs(dylibPath)
		if err != nil {
			return fmt.Errorf("invalid dylib path %s: %w", dylibPath, err)
		}
		if _, err := os.Stat(abs); err != nil {
			return fmt.Errorf("dylib not found: %s", abs)
		}
		dm, err := macho.Open(abs)
		if err != nil {
			return fmt.Errorf("invalid dylib (not Mach-O): %s", abs)
		}
		dm.Close()
		o.dylibFiles[i] = abs
	}

	if o.checkSig && len(o.provFiles) == 0 {
		return certcheck.CheckFile(absPath, o.password)
	}

	isZip := archive.IsZipFile(absPath)
	isDir := func() bool {
		fi, err := os.Stat(absPath)
		return err == nil && fi.IsDir()
	}()

	if !isZip && !isDir {
		return runMachO(absPath, o, start)
	}

	noSign := len(o.provFiles) == 0 && !o.adhoc && o.pkeyFile == "" && o.certFile == ""
	if noSign && len(o.dylibFiles) == 0 && len(o.rmDylibs) == 0 {
		return inspectBundle(absPath, isZip, o.tempFolder)
	}

	if o.outputFile == "" {
		if o.install {
			o.outputFile = filepath.Join(
				o.tempFolder,
				fmt.Sprintf("askua_temp_%d.ipa", time.Now().UnixMicro()),
			)
			defer os.Remove(o.outputFile)
		} else if isZip {
			return fmt.Errorf("use -o to specify the output IPA file")
		}
	}

	if len(o.provFiles) == 0 && !o.adhoc {
		return fmt.Errorf("at least one provisioning profile (-m) or --adhoc is required")
	}
	if len(o.provFiles) == 0 {
		o.provFiles = []string{""}
	}

	assets := make([]*cert.Asset, 0, len(o.provFiles))
	for _, prov := range o.provFiles {
		a := &cert.Asset{}
		if err := a.Init(
			o.certFile, o.pkeyFile, prov, o.entitleFile, o.password,
			o.adhoc, o.sha256Only, false,
		); err != nil {
			logger.Errorf("- Failed to init provisioning profile %s: %v\n", prov, err)
			continue
		}
		assets = append(assets, a)
	}
	if len(assets) == 0 {
		return fmt.Errorf("no valid signing assets could be loaded")
	}

	sigFolder := absPath
	if isZip {
		o.force = true
		sigFolder = filepath.Join(
			o.tempFolder,
			fmt.Sprintf("askua_folder_%d", time.Now().UnixMicro()),
		)
		defer os.RemoveAll(sigFolder)
		logger.Printf("- Unzip:\t%s (%s) -> %s ...\n",
			absPath, archive.FormatSize(absPath), sigFolder)
		if err := archive.Extract(absPath, sigFolder); err != nil {
			return fmt.Errorf("unzip failed: %w", err)
		}
		logger.Success("- Unzip OK!\n")
	}

	signStart := time.Now()
	b := &bundle.Bundle{
		BundleID:                 o.bundleID,
		BundleVersion:            o.bundleVer,
		DisplayName:              o.bundleName,
		MinVersion:               o.minVersion,
		InjectDylibs:             o.dylibFiles,
		RemoveDylibs:             o.rmDylibs,
		WeakInject:               o.weakInject,
		Force:                    o.force,
		EnableCache:              !isZip,
		RemoveProvision:          o.removeProvision,
		EnableDocuments:          o.enableDocs,
		RemoveExtensions:         o.removeExts,
		RemoveWatchApp:           o.removeWatch,
		RemoveUISupportedDevices: o.removeUISD,
	}
	if err := b.SignFolder(assets, sigFolder); err != nil {
		logger.Errorf("- Signed Failed! (%v)\n", time.Since(signStart))
		return err
	}
	logger.Successf("- Signed OK! (%v)\n", time.Since(signStart))

	appFolder, err := bundle.FindAppFolder(sigFolder)
	if err != nil {
		return err
	}

	if o.outputFile != "" {
		baseFolder, err := bundle.PayloadRoot(appFolder)
		if err != nil {
			return fmt.Errorf("cannot build IPA: %w", err)
		}
		logger.Printf("- Archiving: \t%s ...\n", o.outputFile)
		archStart := time.Now()
		if err := archive.Archive(baseFolder, o.outputFile, o.zipLevel); err != nil {
			return fmt.Errorf("archive failed: %w", err)
		}
		logger.Successf("- Archive OK! (%v) (%s)\n",
			time.Since(archStart), archive.FormatSize(o.outputFile))
	}

	if o.metadataDir != "" {
		if err := metadata.Extract(appFolder, o.metadataDir, o.outputFile); err != nil {
			logger.Warnf("- Warning: metadata extraction failed: %v\n", err)
		} else {
			logger.Printf("- Metadata:\t%s\n", o.metadataDir)
		}
	}

	if o.install && o.outputFile != "" {
		logger.Printf("- Installing: %s\n", o.outputFile)
		icmd := exec.Command(o.installerPath, "install", o.outputFile)
		icmd.Stdout = os.Stdout
		icmd.Stderr = os.Stderr
		if err := icmd.Run(); err != nil {
			return fmt.Errorf("install failed: %w", err)
		}
	}

	logger.Printf("- Done. (%v)\n", time.Since(start))
	return nil
}

func runMachO(path string, o runOpts, start time.Time) error {
	m, err := macho.Open(path)
	if err != nil {
		return fmt.Errorf("invalid Mach-O file %s: %w", path, err)
	}
	defer m.Close()

	if !o.adhoc && len(o.dylibFiles) == 0 && len(o.rmDylibs) == 0 &&
		(o.pkeyFile == "" || len(o.provFiles) == 0) {
		m.PrintInfo()
		return nil
	}

	a := &cert.Asset{}
	prov := ""
	if len(o.provFiles) > 0 {
		prov = o.provFiles[0]
	}
	if err := a.Init(
		o.certFile, o.pkeyFile, prov, o.entitleFile, o.password,
		o.adhoc, o.sha256Only, true,
	); err != nil {
		return fmt.Errorf("init signing asset: %w", err)
	}

	for _, dylib := range o.dylibFiles {
		if err := m.InjectDylib(o.weakInject, dylib); err != nil {
			return fmt.Errorf("inject dylib %s: %w", dylib, err)
		}
	}

	if len(o.rmDylibs) > 0 {
		m.RemoveDylibs(macho.DylibSet(o.rmDylibs))
	}

	adhocNote := ""
	if o.adhoc {
		adhocNote = " (Ad-hoc)"
	}
	logger.Printf("- Signing:\t%s%s\n", path, adhocNote)
	if err := m.Sign(a, o.force, o.bundleID, "", "", ""); err != nil {
		logger.Errorf("- Signed Failed! (%v)\n", time.Since(start))
		return err
	}
	logger.Successf("- Signed OK! (%v)\n", time.Since(start))
	return nil
}

func inspectBundle(absPath string, isZip bool, tempFolder string) error {
	sigFolder := absPath
	tmpDir := ""
	if isZip {
		tmpDir = filepath.Join(tempFolder, fmt.Sprintf("askua_folder_%d", time.Now().UnixMicro()))
		if err := archive.Extract(absPath, tmpDir); err != nil {
			return fmt.Errorf("extract IPA: %w", err)
		}
		sigFolder = tmpDir
		defer os.RemoveAll(tmpDir)
	}

	appFolder, err := bundle.FindAppFolder(sigFolder)
	if err != nil {
		return fmt.Errorf("find .app folder: %w", err)
	}

	infoPlistPath := filepath.Join(appFolder, "Info.plist")
	data, err := os.ReadFile(infoPlistPath)
	if err != nil {
		return fmt.Errorf("read Info.plist: %w", err)
	}
	var info map[string]interface{}
	if _, err := plist.Unmarshal(data, &info); err != nil {
		return fmt.Errorf("parse Info.plist: %w", err)
	}

	get := func(key string) string {
		if v, ok := info[key].(string); ok {
			return v
		}
		return ""
	}

	name := get("CFBundleDisplayName")
	if name == "" {
		name = get("CFBundleName")
	}
	version := get("CFBundleShortVersionString")
	if version == "" {
		version = get("CFBundleVersion")
	}

	exe := get("CFBundleExecutable")
	signed := false
	if exe != "" {
		if m, err := macho.Open(filepath.Join(appFolder, exe)); err == nil {
			signed = m.CheckSignature()
			m.Close()
		}
	}

	logger.Printf("------------------------------------------------------------------\n")
	logger.Printf("- Bundle Info:\n")
	logger.Printf("\tName:       \t%s\n", name)
	logger.Printf("\tBundleID:   \t%s\n", get("CFBundleIdentifier"))
	logger.Printf("\tVersion:    \t%s (%s)\n", version, get("CFBundleVersion"))
	logger.Printf("\tMinOS:      \t%s\n", get("MinimumOSVersion"))
	logger.Printf("\tExecutable: \t%s\n", exe)
	logger.Printf("\tSigned:     \t%v\n", signed)
	if isZip {
		logger.Printf("\tIPA:        \t%s (%s)\n", filepath.Base(absPath), archive.FormatSize(absPath))
	}
	logger.Printf("------------------------------------------------------------------\n")
	return nil
}
