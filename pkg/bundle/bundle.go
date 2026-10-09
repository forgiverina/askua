package bundle

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/forgiverina/askua/pkg/cert"
	"github.com/forgiverina/askua/pkg/logger"
	"github.com/forgiverina/askua/pkg/macho"
)

type Bundle struct {
	BundleID      string
	BundleVersion string
	DisplayName   string
	MinVersion    string

	InjectDylibs []string
	RemoveDylibs []string
	WeakInject   bool

	Force           bool
	EnableCache     bool
	RemoveProvision bool

	EnableDocuments          bool
	RemoveExtensions         bool
	RemoveWatchApp           bool
	RemoveUISupportedDevices bool

	appFolder   string
	assets      []*cert.Asset
	force       bool
	injectPaths []string
	rmDylibs    map[string]struct{}
}

type matchResult int

const (
	matchNone matchResult = iota
	matchWildcard
	matchExact
)

func (b *Bundle) pickAsset(bundleID string) *cert.Asset {
	if len(b.assets) == 1 || bundleID == "" {
		return b.assets[0]
	}
	var wildcard *cert.Asset
	for _, a := range b.assets {
		switch matchAppID(a.AppID, bundleID) {
		case matchExact:
			return a
		case matchWildcard:
			if wildcard == nil {
				wildcard = a
			}
		}
	}
	if wildcard != nil {
		return wildcard
	}
	return b.assets[0]
}

func matchAppID(appID, bundleID string) matchResult {
	dot := strings.IndexByte(appID, '.')
	if dot < 0 {
		return matchNone
	}
	suffix := appID[dot+1:]
	if suffix == "*" {
		return matchWildcard
	}
	if suffix == bundleID {
		return matchExact
	}
	if strings.HasSuffix(suffix, ".*") {
		prefix := suffix[:len(suffix)-2]
		if bundleID == prefix || strings.HasPrefix(bundleID, prefix+".") {
			return matchWildcard
		}
	}
	return matchNone
}

func (b *Bundle) SignFolder(assets []*cert.Asset, folder string) error {
	if len(assets) == 0 {
		return fmt.Errorf("no signing assets")
	}
	b.assets = assets
	b.force = b.Force
	b.injectPaths = nil
	b.rmDylibs = macho.DylibSet(b.RemoveDylibs)

	appFolder, err := FindAppFolder(folder)
	if err != nil {
		return fmt.Errorf("find app folder in %s: %w", folder, err)
	}
	b.appFolder = appFolder

	b.applyModifications()

	if b.BundleID != "" || b.DisplayName != "" || b.BundleVersion != "" {
		b.force = true
		if err := b.modifyBundleInfo(b.BundleID, b.BundleVersion, b.DisplayName); err != nil {
			return err
		}
	}

	if len(b.InjectDylibs) > 0 {
		b.force = true
		for _, dylib := range b.InjectDylibs {
			dst := filepath.Join(b.appFolder, filepath.Base(dylib))
			if err := copyFile(dylib, dst); err != nil {
				logger.Warnf("- Warning: failed to copy dylib %s: %v\n", dylib, err)
				continue
			}
			b.injectPaths = append(b.injectPaths, "@executable_path/"+filepath.Base(dylib))
		}
	}

	cacheFile := filepath.Join(".askua_cache", sha1Hex(b.appFolder)+".json")
	if _, serr := os.Stat(cacheFile); serr != nil {
		b.force = true
	}

	var root *folderNode
	if b.force {
		root = &folderNode{Path: "/", Root: b.appFolder}
		if err := b.getSignFolderInfo(b.appFolder, root, true); err != nil {
			return fmt.Errorf("get app info: %w", err)
		}
		if err := b.getObjectsToSign(b.appFolder, root); err != nil {
			return err
		}
		getNodeChangedFiles(root)
	} else {
		data, err := os.ReadFile(cacheFile)
		if err != nil {
			return fmt.Errorf("read cache %s: %w", cacheFile, err)
		}
		root = &folderNode{}
		if err := json.Unmarshal(data, root); err != nil {
			return fmt.Errorf("parse cache: %w", err)
		}
	}

	rootAsset := b.pickAsset(root.BundleID)
	logger.Printf("- Signing: \t%s ...\n", b.appFolder)
	logger.Printf("- AppName: \t%s\n", root.Name)
	logger.Printf("- BundleId: \t%s\n", root.BundleID)
	logger.Printf("- Version: \t%s\n", root.BundleVersion)
	logger.Printf("- TeamId: \t%s\n", rootAsset.TeamID)
	logger.Printf("- SubjectCN: \t%s\n", rootAsset.SubjectCN)
	if b.force {
		logger.Printf("- ReadCache: \tNO\n")
	} else {
		logger.Printf("- ReadCache: \tYES\n")
	}

	if err := b.signNode(root); err != nil {
		return err
	}

	if b.EnableCache {
		if err := os.MkdirAll(".askua_cache", 0755); err == nil {
			if data, err := json.Marshal(root); err == nil {
				_ = os.WriteFile(cacheFile, data, 0644)
			}
		}
	}
	return nil
}

func (b *Bundle) signFiles(files []string, asset *cert.Asset) error {
	if len(files) == 0 {
		return nil
	}
	errs := make([]error, len(files))
	jobs := make(chan int)
	workers := min(runtime.GOMAXPROCS(0), len(files))

	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for i := range jobs {
				relFile := files[i]
				logger.Debugf("- SignFile: \t%s\n", relFile)
				m, err := macho.Open(filepath.Join(b.appFolder, relFile))
				if err != nil {
					logger.Warnf("- Warning: skipping non-Mach-O: %s\n", relFile)
					continue
				}
				err = m.Sign(asset, b.force, "", "", "", "")
				m.Close()
				if err != nil {
					errs[i] = fmt.Errorf("sign file %s: %w", relFile, err)
				}
			}
		}()
	}
	for i := range files {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return errors.Join(errs...)
}

func (b *Bundle) signNode(node *folderNode) error {
	nodeAsset := b.pickAsset(node.BundleID)

	if err := b.signFiles(node.Files, nodeAsset); err != nil {
		return err
	}

	for _, sub := range node.Folders {
		if err := b.signNode(sub); err != nil {
			return err
		}
	}

	basePath := b.appFolder
	if node.Path != "/" {
		basePath = filepath.Join(b.appFolder, filepath.FromSlash(node.Path))
	}
	isRoot := node.Path == "/"

	infoSHA1, err := base64.StdEncoding.DecodeString(node.InfoSHA1)
	if err != nil || len(infoSHA1) == 0 {
		return fmt.Errorf("invalid InfoSHA1 for %s", node.Path)
	}
	infoSHA256, err := base64.StdEncoding.DecodeString(node.InfoSHA256)
	if err != nil || len(infoSHA256) == 0 {
		return fmt.Errorf("invalid InfoSHA256 for %s", node.Path)
	}

	exePath := filepath.Join(basePath, node.BundleExe)
	displayPath := node.Path
	if isRoot {
		displayPath = filepath.Base(b.appFolder)
	}
	logger.Printf("- SignFolder: %s, (%s)\n", displayPath, node.BundleExe)

	forceSign := b.force

	if isRoot && (len(b.injectPaths) > 0 || len(b.rmDylibs) > 0) {
		m, err := macho.Open(exePath)
		if err != nil {
			return fmt.Errorf("open executable for dylib ops %s: %w", exePath, err)
		}
		for _, dylibPath := range b.injectPaths {
			if err := m.InjectDylib(b.WeakInject, dylibPath); err != nil {
				logger.Warnf("- Warning: inject dylib %s: %v\n", dylibPath, err)
				continue
			}
			forceSign = true
		}
		if len(b.rmDylibs) > 0 {
			m.RemoveDylibs(b.rmDylibs)
			for name := range b.rmDylibs {
				if base, ok := strings.CutPrefix(name, "@executable_path/"); ok {
					_ = os.Remove(filepath.Join(b.appFolder, filepath.FromSlash(base)))
				}
			}
			forceSign = true
		}
		m.Close()
	}

	if err := b.placeProvision(basePath, isRoot, nodeAsset); err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Join(basePath, "_CodeSignature"), 0755); err != nil {
		return fmt.Errorf("mkdir _CodeSignature: %w", err)
	}
	codeResFile := filepath.Join(basePath, "_CodeSignature", "CodeResources")

	var codeResData string
	existing, readErr := os.ReadFile(codeResFile)
	switch {
	case forceSign || readErr != nil:
		codeResData, err = generateCodeResources(basePath, node.BundleExe)
		if err != nil {
			return fmt.Errorf("generate CodeResources %s: %w", basePath, err)
		}
	case len(node.Changed) > 0:
		codeResData, err = updateCodeResources(existing, b.appFolder, node.Path, node.Changed)
		if err != nil {
			return fmt.Errorf("update CodeResources %s: %w", basePath, err)
		}
	default:
		codeResData = string(existing)
	}

	if err := os.WriteFile(codeResFile, []byte(codeResData), 0644); err != nil {
		return fmt.Errorf("write CodeResources: %w", err)
	}

	m, err := macho.Open(exePath)
	if err != nil {
		return fmt.Errorf("open executable %s: %w", exePath, err)
	}
	defer m.Close()
	if err := m.Sign(
		nodeAsset, forceSign,
		node.BundleID, string(infoSHA1), string(infoSHA256), codeResData,
	); err != nil {
		return fmt.Errorf("sign executable %s: %w", exePath, err)
	}
	return nil
}

func (b *Bundle) placeProvision(basePath string, isRoot bool, asset *cert.Asset) error {
	ext := strings.ToLower(filepath.Ext(basePath))
	if !isRoot && ext != ".app" && ext != ".appex" {
		return nil
	}
	provPath := filepath.Join(basePath, "embedded.mobileprovision")
	if b.RemoveProvision {
		if err := os.Remove(provPath); err == nil {
			logger.Printf("- Removed embedded.mobileprovision\n")
		}
		return nil
	}
	if len(asset.ProvData) == 0 {
		if isRoot {
			_ = os.Remove(provPath)
		}
		return nil
	}
	if err := os.WriteFile(provPath, asset.ProvData, 0644); err != nil {
		return fmt.Errorf("write embedded.mobileprovision: %w", err)
	}
	return nil
}

func (b *Bundle) applyModifications() {
	if b.EnableDocuments {
		if err := modifyInfoPlist(b.appFolder, func(info map[string]interface{}) {
			info["UISupportsDocumentBrowser"] = true
			info["UIFileSharingEnabled"] = true
		}); err == nil {
			b.force = true
			logger.Printf("- Enabled documents support\n")
		}
	}

	if b.MinVersion != "" {
		if err := modifyInfoPlist(b.appFolder, func(info map[string]interface{}) {
			old, _ := info["MinimumOSVersion"].(string)
			info["MinimumOSVersion"] = b.MinVersion
			logger.Printf("- MinimumOSVersion: %s -> %s\n", old, b.MinVersion)
		}); err == nil {
			b.force = true
		}
	}

	if b.RemoveExtensions {
		for _, dir := range []string{"PlugIns", "Extensions"} {
			path := filepath.Join(b.appFolder, dir)
			if info, err := os.Stat(path); err == nil && info.IsDir() {
				if err := os.RemoveAll(path); err == nil {
					logger.Printf("- Removed %s\n", dir)
					b.force = true
				}
			}
		}
	}

	if b.RemoveWatchApp {
		for _, dir := range []string{"Watch", "WatchKit", "com.apple.WatchPlaceholder"} {
			path := filepath.Join(b.appFolder, dir)
			if info, err := os.Stat(path); err == nil && info.IsDir() {
				if err := os.RemoveAll(path); err == nil {
					logger.Printf("- Removed %s\n", dir)
					b.force = true
				}
			}
		}
	}

	if b.RemoveUISupportedDevices {
		if err := modifyInfoPlist(b.appFolder, func(info map[string]interface{}) {
			if _, ok := info["UISupportedDevices"]; ok {
				delete(info, "UISupportedDevices")
				b.force = true
				logger.Printf("- Removed UISupportedDevices\n")
			}
		}); err != nil {
			logger.Warnf("- Warning: could not remove UISupportedDevices: %v\n", err)
		}
	}
}

func PayloadRoot(appFolder string) (string, error) {
	payload := filepath.Dir(appFolder)
	if filepath.Base(payload) != "Payload" {
		return "", fmt.Errorf("%s is not inside a Payload directory", appFolder)
	}
	return filepath.Dir(payload), nil
}
