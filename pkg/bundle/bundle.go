package bundle

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/forgiverina/askua/pkg/cert"
	"github.com/forgiverina/askua/pkg/logger"
	"github.com/forgiverina/askua/pkg/macho"
)

type Bundle struct {
	appFolder  string
	assets     []*cert.Asset
	force      bool
	weakInject bool
	rmProv     bool

	injectDylibs []string
	rmDylibs     map[string]struct{}

	EnableDocuments          bool
	MinVersion               string
	RemoveExtensions         bool
	RemoveWatchApp           bool
	RemoveUISupportedDevices bool
}

type matchResult int

const (
	matchNone     matchResult = iota
	matchWildcard             // TEAMID.* or TEAMID.prefix.*
	matchExact                // TEAMID.bundleID
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

func (b *Bundle) SignFolder(
	assets []*cert.Asset,
	folder, bundleID, bundleVersion, displayName string,
	injectDylibs, removeDylibNames []string,
	force, weakInject, enableCache, removeProvision bool,
) error {
	if len(assets) == 0 {
		return fmt.Errorf("no signing assets")
	}
	b.assets = assets
	asset := assets[0]
	b.force = force
	b.weakInject = weakInject
	b.rmProv = removeProvision
	b.injectDylibs = nil
	b.rmDylibs = make(map[string]struct{})
	for _, name := range removeDylibNames {
		if strings.Contains(name, "/") {
			b.rmDylibs[name] = struct{}{}
		} else {
			b.rmDylibs["@executable_path/"+name] = struct{}{}
		}
	}

	appFolder, err := FindAppFolder(folder)
	if err != nil {
		return fmt.Errorf("find app folder in %s: %w", folder, err)
	}
	b.appFolder = appFolder

	b.applyModifications()

	if bundleID != "" || displayName != "" || bundleVersion != "" {
		b.force = true
		if err := b.modifyBundleInfo(bundleID, bundleVersion, displayName); err != nil {
			return err
		}
	}

	_ = os.Remove(filepath.Join(b.appFolder, "embedded.mobileprovision"))
	if len(asset.ProvData) > 0 {
		if err := os.WriteFile(
			filepath.Join(b.appFolder, "embedded.mobileprovision"),
			asset.ProvData, 0644,
		); err != nil {
			return fmt.Errorf("write embedded.mobileprovision: %w", err)
		}
	}

	if len(injectDylibs) > 0 {
		b.force = true
		for _, dylib := range injectDylibs {
			dst := filepath.Join(b.appFolder, filepath.Base(dylib))
			if err := copyFile(dylib, dst); err != nil {
				logger.Warnf("- Warning: failed to copy dylib %s: %v\n", dylib, err)
				continue
			}
			b.injectDylibs = append(b.injectDylibs, "@executable_path/"+filepath.Base(dylib))
		}
	}

	cacheKey := sha1Hex(b.appFolder)
	cacheFile := filepath.Join(".askua_cache", cacheKey+".json")
	if _, serr := os.Stat(cacheFile); os.IsNotExist(serr) {
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

	logger.Printf("- Signing: \t%s ...\n", b.appFolder)
	logger.Printf("- AppName: \t%s\n", root.Name)
	logger.Printf("- BundleId: \t%s\n", root.BundleID)
	logger.Printf("- Version: \t%s\n", root.BundleVersion)
	logger.Printf("- TeamId: \t%s\n", asset.TeamID)
	logger.Printf("- SubjectCN: \t%s\n", asset.SubjectCN)
	if b.force {
		logger.Printf("- ReadCache: \tNO\n")
	} else {
		logger.Printf("- ReadCache: \tYES\n")
	}

	if err := b.signNode(root); err != nil {
		return err
	}

	if enableCache {
		if err := os.MkdirAll(".askua_cache", 0755); err == nil {
			if data, err := json.Marshal(root); err == nil {
				_ = os.WriteFile(cacheFile, data, 0644)
			}
		}
	}
	return nil
}

func (b *Bundle) signNode(node *folderNode) error {
	primaryAsset := b.assets[0]
	nodeAsset := b.pickAsset(node.BundleID)

	for _, relFile := range node.Files {
		absFile := filepath.Join(b.appFolder, relFile)
		logger.Debugf("- SignFile: \t%s\n", relFile)
		m, err := macho.Open(absFile)
		if err != nil {
			logger.Warnf("- Warning: skipping non-Mach-O: %s\n", relFile)
			continue
		}
		if err := m.Sign(primaryAsset, b.force, "", "", "", ""); err != nil {
			return fmt.Errorf("sign file %s: %w", relFile, err)
		}
	}

	for _, sub := range node.Folders {
		if err := b.signNode(sub); err != nil {
			return err
		}
	}

	basePath := b.appFolder
	if node.Path != "/" {
		basePath = filepath.Join(b.appFolder, node.Path)
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

	if isRoot && (len(b.injectDylibs) > 0 || len(b.rmDylibs) > 0) {
		m, err := macho.Open(exePath)
		if err != nil {
			return fmt.Errorf("open executable for dylib ops %s: %w", exePath, err)
		}
		for _, dylibPath := range b.injectDylibs {
			if err := m.InjectDylib(b.weakInject, dylibPath); err != nil {
				logger.Warnf("- Warning: inject dylib %s: %v\n", dylibPath, err)
				continue
			}
			forceSign = true
		}
		if len(b.rmDylibs) > 0 {
			m.RemoveDylibs(b.rmDylibs)
			for name := range b.rmDylibs {
				base := strings.TrimPrefix(name, "@executable_path/")
				_ = os.Remove(filepath.Join(b.appFolder, base))
			}
			forceSign = true
		}
		m.Close()
	}

	if err := os.MkdirAll(filepath.Join(basePath, "_CodeSignature"), 0755); err != nil {
		return fmt.Errorf("mkdir _CodeSignature: %w", err)
	}
	codeResFile := filepath.Join(basePath, "_CodeSignature", "CodeResources")

	var codeResData string
	switch {
	case forceSign:
		cr, err := generateCodeResources(basePath, node.BundleExe, b.rmProv)
		if err != nil {
			return fmt.Errorf("generate CodeResources %s: %w", basePath, err)
		}
		codeResData = cr

	case len(node.Changed) > 0:
		existing, err := os.ReadFile(codeResFile)
		if err != nil {
			cr, err := generateCodeResources(basePath, node.BundleExe, b.rmProv)
			if err != nil {
				return fmt.Errorf("generate CodeResources %s: %w", basePath, err)
			}
			codeResData = cr
		} else {
			codeResData, err = updateCodeResources(existing, b.appFolder, node.Path, node.Changed)
			if err != nil {
				return fmt.Errorf("update CodeResources %s: %w", basePath, err)
			}
		}

	default:
		existing, err := os.ReadFile(codeResFile)
		if err != nil {
			cr, err := generateCodeResources(basePath, node.BundleExe, b.rmProv)
			if err != nil {
				return fmt.Errorf("generate CodeResources %s: %w", basePath, err)
			}
			codeResData = cr
		} else {
			codeResData = string(existing)
		}
	}

	if err := os.WriteFile(codeResFile, []byte(codeResData), 0644); err != nil {
		return fmt.Errorf("write CodeResources: %w", err)
	}

	ext := strings.ToLower(filepath.Ext(basePath))
	if !isRoot && !b.rmProv && (ext == ".app" || ext == ".appex") {
		if len(nodeAsset.ProvData) > 0 {
			_ = os.WriteFile(filepath.Join(basePath, "embedded.mobileprovision"), nodeAsset.ProvData, 0644)
		}
	}

	m, err := macho.Open(exePath)
	if err != nil {
		return fmt.Errorf("open executable %s: %w", exePath, err)
	}
	if err := m.Sign(
		nodeAsset, forceSign,
		node.BundleID, string(infoSHA1), string(infoSHA256), codeResData,
	); err != nil {
		return fmt.Errorf("sign executable %s: %w", exePath, err)
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
