package bundle

import (
	"crypto/sha1" //nolint:gosec
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/forgiverina/askua/pkg/logger"
	"howett.net/plist"
)

type folderNode struct {
	Path          string        `json:"path"`
	Root          string        `json:"root,omitempty"`
	BundleID      string        `json:"bundle_id"`
	BundleVersion string        `json:"bundle_version"`
	BundleExe     string        `json:"bundle_executable"`
	Name          string        `json:"name,omitempty"`
	InfoSHA1      string        `json:"sha1"`
	InfoSHA256    string        `json:"sha256"`
	Files         []string      `json:"files,omitempty"`
	Folders       []*folderNode `json:"folders,omitempty"`
	Changed       []string      `json:"changed,omitempty"`
}

func FindAppFolder(folder string) (string, error) {
	if strings.HasSuffix(folder, ".app") || strings.HasSuffix(folder, ".appex") {
		return folder, nil
	}

	var found string
	filepath.WalkDir(folder, func(path string, d fs.DirEntry, err error) error { //nolint:errcheck
		if err != nil || !d.IsDir() {
			return nil
		}
		name := d.Name()
		if name == "__MACOSX" {
			return fs.SkipDir
		}
		if path != folder && (strings.HasSuffix(path, ".app") || strings.HasSuffix(path, ".appex")) {
			found = path
			return fs.SkipAll
		}
		return nil
	})

	if found == "" {
		return "", fmt.Errorf("no .app or .appex found in %s", folder)
	}
	return found, nil
}

func (b *Bundle) getSignFolderInfo(folder string, node *folderNode, getName bool) error {
	infoPlistPath := filepath.Join(folder, "Info.plist")
	data, err := os.ReadFile(infoPlistPath)
	if err != nil {
		return fmt.Errorf("read Info.plist in %s: %w", folder, err)
	}

	var info map[string]interface{}
	if _, err := plist.Unmarshal(data, &info); err != nil {
		return fmt.Errorf("parse Info.plist in %s: %w", folder, err)
	}

	node.BundleID = plistStr(info, "CFBundleIdentifier")
	node.BundleExe = plistStr(info, "CFBundleExecutable")
	node.BundleVersion = plistStr(info, "CFBundleVersion")
	if node.BundleID == "" || node.BundleExe == "" {
		return fmt.Errorf("missing CFBundleIdentifier or CFBundleExecutable in %s", folder)
	}

	h1 := sha1.Sum(data) //nolint:gosec
	h256 := sha256.Sum256(data)
	node.InfoSHA1 = base64.StdEncoding.EncodeToString(h1[:])
	node.InfoSHA256 = base64.StdEncoding.EncodeToString(h256[:])

	if getName {
		name := plistStr(info, "CFBundleDisplayName")
		if name == "" {
			name = plistStr(info, "CFBundleName")
		}
		node.Name = name
	}
	return nil
}

func (b *Bundle) getObjectsToSign(folder string, root *folderNode) error {
	var bundles []string

	if err := filepath.WalkDir(folder, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if path != folder && (strings.HasSuffix(path, ".app") || strings.HasSuffix(path, ".appex") ||
				strings.HasSuffix(path, ".framework") || strings.HasSuffix(path, ".xctest")) {
				bundles = append(bundles, path)
			}
			return nil
		}
		if strings.Contains(path, ".dSYM") || strings.Contains(path, "_WatchKitStub") {
			return nil
		}
		if nonMachOExt(d.Name()) {
			return nil
		}
		if isMachO(path) {
			root.Files = append(root.Files, strings.TrimPrefix(path, b.appFolder+"/"))
		}
		return nil
	}); err != nil {
		return err
	}

	sort.Slice(bundles, func(i, j int) bool {
		return strings.Count(bundles[i], "/") > strings.Count(bundles[j], "/")
	})

	for _, bp := range bundles {
		node := &folderNode{
			Path: strings.TrimPrefix(bp, b.appFolder+"/"),
		}
		if err := b.getSignFolderInfo(bp, node, false); err != nil {
			logger.Warnf("- Warning: skip bundle %s: %v\n", bp, err)
			continue
		}
		root.Folders = append(root.Folders, node)
	}
	return nil
}

func nonMachOExt(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".png", ".jpg", ".jpeg", ".gif", ".tiff", ".bmp", ".pdf",
		".plist", ".json", ".xml", ".html", ".css", ".js",
		".strings", ".stringsdict", ".car",
		".mp3", ".mp4", ".m4a", ".m4v", ".wav", ".aac",
		".ttf", ".otf", ".woff", ".woff2", ".txt", ".md", ".rtf":
		return true
	}
	return false
}

func getNodeChangedFiles(node *folderNode) {
	for _, sub := range node.Folders {
		getNodeChangedFiles(sub)
	}

	var changed []string
	collectChanged(node, &changed)
	node.Changed = append(node.Changed, changed...)

	if node.Path == "/" {
		node.Changed = append(node.Changed, "embedded.mobileprovision")
	}
}

func collectChanged(node *folderNode, out *[]string) {
	for _, f := range node.Files {
		*out = append(*out, f)
	}
	for _, sub := range node.Folders {
		collectChanged(sub, out)
		*out = append(*out,
			sub.Path+"/_CodeSignature/CodeResources",
			sub.Path+"/"+sub.BundleExe,
		)
	}
}
