package metadata

import (
	"crypto/sha1" //nolint:gosec
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"howett.net/plist"
)

type Info struct {
	AppName             string `json:"AppName"`
	AppVersion          string `json:"AppVersion"`
	AppBundleIdentifier string `json:"AppBundleIdentifier"`
	AppSize             int64  `json:"AppSize"`
	IconName            string `json:"IconName"`
	FileName            string `json:"FileName"`
	Timestamp           int64  `json:"Timestamp"`
}

func Extract(appFolder, outputDir, ipaFile string) error {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	infoPlistPath := filepath.Join(appFolder, "Info.plist")
	plistData, err := os.ReadFile(infoPlistPath)
	if err != nil {
		return fmt.Errorf("read Info.plist: %w", err)
	}

	var info map[string]interface{}
	if _, err := plist.Unmarshal(plistData, &info); err != nil {
		return fmt.Errorf("parse Info.plist: %w", err)
	}

	appName := plistStr(info, "CFBundleDisplayName")
	if appName == "" {
		appName = plistStr(info, "CFBundleName")
	}
	appVersion := plistStr(info, "CFBundleShortVersionString")
	if appVersion == "" {
		appVersion = plistStr(info, "CFBundleVersion")
	}
	bundleID := plistStr(info, "CFBundleIdentifier")

	iconNames := extractIconNames(info)
	iconSrc := findLargestIcon(appFolder, iconNames)

	var iconName string
	if iconSrc != "" {
		tmpDst := filepath.Join(outputDir, ".icon_tmp")
		if name, err := copyAndHash(iconSrc, tmpDst); err == nil {
			iconName = name + ".png"
			_ = os.Rename(tmpDst, filepath.Join(outputDir, iconName))
		} else {
			_ = os.Remove(tmpDst)
		}
	}

	var ipaSize int64
	var fileName string
	if ipaFile != "" {
		if fi, err := os.Stat(ipaFile); err == nil {
			ipaSize = fi.Size()
		}
		fileName = filepath.Base(ipaFile)
	}

	meta := Info{
		AppName:             appName,
		AppVersion:          appVersion,
		AppBundleIdentifier: bundleID,
		AppSize:             ipaSize,
		IconName:            iconName,
		FileName:            fileName,
		Timestamp:           time.Now().Unix(),
	}

	metaPath := filepath.Join(outputDir, "metadata.json")
	out, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}
	if err := os.WriteFile(metaPath, out, 0644); err != nil {
		return fmt.Errorf("write metadata.json: %w", err)
	}

	return nil
}

func extractIconNames(info map[string]interface{}) []string {
	var names []string

	if icons, ok := info["CFBundleIcons"].(map[string]interface{}); ok {
		if primary, ok := icons["CFBundlePrimaryIcon"].(map[string]interface{}); ok {
			if files, ok := primary["CFBundleIconFiles"].([]interface{}); ok {
				for _, f := range files {
					if s, ok := f.(string); ok && s != "" {
						names = append(names, s)
					}
				}
			}
		}
	}

	if len(names) == 0 {
		if files, ok := info["CFBundleIconFiles"].([]interface{}); ok {
			for _, f := range files {
				if s, ok := f.(string); ok && s != "" {
					names = append(names, s)
				}
			}
		}
	}

	if len(names) == 0 {
		if s := plistStr(info, "CFBundleIconFile"); s != "" {
			names = append(names, s)
		}
	}
	return names
}

func findLargestIcon(appFolder string, prefixes []string) string {
	if len(prefixes) == 0 {
		return ""
	}
	var bestPath string
	var bestSize int64

	entries, err := os.ReadDir(appFolder)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		base := strings.TrimSuffix(name, filepath.Ext(name))
		base = strings.TrimSuffix(base, "@2x")
		base = strings.TrimSuffix(base, "@3x")
		matched := false
		for _, p := range prefixes {
			if strings.HasPrefix(base, p) || base == p {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		if fi.Size() > bestSize {
			bestSize = fi.Size()
			bestPath = filepath.Join(appFolder, name)
		}
	}
	return bestPath
}

func copyAndHash(src, dst string) (string, error) {
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return "", err
	}
	defer out.Close()
	h := sha1.New() //nolint:gosec
	if _, err := io.Copy(io.MultiWriter(out, h), in); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func plistStr(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}
