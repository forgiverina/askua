package bundle

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/forgiverina/askua/pkg/logger"
	"howett.net/plist"
)

func (b *Bundle) modifyBundleInfo(newBundleID, newVersion, newDisplayName string) error {
	infoPlistPath := filepath.Join(b.appFolder, "Info.plist")
	data, err := os.ReadFile(infoPlistPath)
	if err != nil {
		return fmt.Errorf("read Info.plist: %w", err)
	}
	var info map[string]interface{}
	if _, err := plist.Unmarshal(data, &info); err != nil {
		return fmt.Errorf("parse Info.plist: %w", err)
	}

	if newBundleID != "" {
		oldID := plistStr(info, "CFBundleIdentifier")
		info["CFBundleIdentifier"] = newBundleID
		logger.Printf("- BundleId: \t%s -> %s\n", oldID, newBundleID)
		b.modifyPluginsBundleID(oldID, newBundleID)
	}

	if newDisplayName != "" {
		oldName := plistStr(info, "CFBundleDisplayName")
		if oldName == "" {
			oldName = plistStr(info, "CFBundleName")
		}
		info["CFBundleName"] = newDisplayName
		info["CFBundleDisplayName"] = newDisplayName
		logger.Printf("- BundleName: %s -> %s\n", oldName, newDisplayName)

		for _, lproj := range []string{"zh_CN.lproj", "zh-Hans.lproj"} {
			stringsPath := filepath.Join(b.appFolder, lproj, "InfoPlist.strings")
			if sdata, err := os.ReadFile(stringsPath); err == nil {
				var sinfo map[string]interface{}
				if _, err := plist.Unmarshal(sdata, &sinfo); err == nil {
					sinfo["CFBundleName"] = newDisplayName
					sinfo["CFBundleDisplayName"] = newDisplayName
					if out, err := plist.Marshal(sinfo, plist.XMLFormat); err == nil {
						_ = os.WriteFile(stringsPath, out, 0644)
					}
				}
			}
		}
	}

	if newVersion != "" {
		oldVer := plistStr(info, "CFBundleVersion")
		info["CFBundleVersion"] = newVersion
		info["CFBundleShortVersionString"] = newVersion
		logger.Printf("- BundleVersion: %s -> %s\n", oldVer, newVersion)
	}

	out, err := plist.Marshal(info, plist.XMLFormat)
	if err != nil {
		return fmt.Errorf("marshal Info.plist: %w", err)
	}
	return os.WriteFile(infoPlistPath, out, 0644)
}

func (b *Bundle) modifyPluginsBundleID(oldID, newID string) {
	filepath.WalkDir(b.appFolder, func(path string, d fs.DirEntry, err error) error { //nolint:errcheck
		if err != nil || !d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".app") && !strings.HasSuffix(path, ".appex") {
			return nil
		}
		if path == b.appFolder {
			return nil
		}
		infoPlistPath := filepath.Join(path, "Info.plist")
		data, err := os.ReadFile(infoPlistPath)
		if err != nil {
			return nil
		}
		var info map[string]interface{}
		if _, err := plist.Unmarshal(data, &info); err != nil {
			return nil
		}

		oldPIID := plistStr(info, "CFBundleIdentifier")
		newPIID := strings.ReplaceAll(oldPIID, oldID, newID)
		info["CFBundleIdentifier"] = newPIID
		logger.Printf("- BundleId: \t%s -> %s, Plugin\n", oldPIID, newPIID)

		if wkc, ok := info["WKCompanionAppBundleIdentifier"].(string); ok {
			nwkc := strings.ReplaceAll(wkc, oldID, newID)
			info["WKCompanionAppBundleIdentifier"] = nwkc
			logger.Printf("- BundleId: \t%s -> %s, Plugin-WKCompanionAppBundleIdentifier\n", wkc, nwkc)
		}

		if nsext, ok := info["NSExtension"].(map[string]interface{}); ok {
			if attrs, ok := nsext["NSExtensionAttributes"].(map[string]interface{}); ok {
				if wkb, ok := attrs["WKAppBundleIdentifier"].(string); ok {
					nwkb := strings.ReplaceAll(wkb, oldID, newID)
					attrs["WKAppBundleIdentifier"] = nwkb
					logger.Printf("- BundleId: \t%s -> %s, NSExtension-NSExtensionAttributes-WKAppBundleIdentifier\n", wkb, nwkb)
				}
			}
		}

		if out, err := plist.Marshal(info, plist.XMLFormat); err == nil {
			_ = os.WriteFile(infoPlistPath, out, 0644)
		}
		return nil
	})
}

func modifyInfoPlist(bundleFolder string, fn func(map[string]interface{})) error {
	path := filepath.Join(bundleFolder, "Info.plist")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var info map[string]interface{}
	if _, err := plist.Unmarshal(data, &info); err != nil {
		return err
	}
	fn(info)
	out, err := plist.Marshal(info, plist.XMLFormat)
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0644)
}

func plistStr(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
