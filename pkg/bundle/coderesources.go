package bundle

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/forgiverina/askua/pkg/logger"
	"howett.net/plist"
)

func generateCodeResources(bundleFolder, bundleExe string, removeProvision bool) (string, error) {
	var allFiles []string
	err := filepath.WalkDir(bundleFolder, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel := strings.TrimPrefix(path, bundleFolder+"/")
		rel = filepath.ToSlash(rel)
		allFiles = append(allFiles, rel)
		return nil
	})
	if err != nil {
		return "", err
	}

	skip := map[string]bool{
		"_CodeSignature/CodeResources": true,
		bundleExe:                      true,
	}

	files := make(map[string]interface{})
	files2 := make(map[string]interface{})

	type hashResult struct {
		h1, h256 []byte
		err      error
	}
	hashes := make([]hashResult, len(allFiles))

	jobs := make(chan int, len(allFiles))
	for i, key := range allFiles {
		if skip[key] || (removeProvision && key == "embedded.mobileprovision") {
			continue
		}
		jobs <- i
	}
	close(jobs)

	numWorkers := runtime.GOMAXPROCS(0)
	var wg sync.WaitGroup
	wg.Add(numWorkers)
	for w := 0; w < numWorkers; w++ {
		go func() {
			defer wg.Done()
			for i := range jobs {
				absPath := filepath.Join(bundleFolder, filepath.FromSlash(allFiles[i]))
				h1, h256, err := fileHashes(absPath)
				hashes[i] = hashResult{h1, h256, err}
			}
		}()
	}
	wg.Wait()

	for i, key := range allFiles {
		if skip[key] {
			continue
		}

		if removeProvision && key == "embedded.mobileprovision" {
			_ = os.Remove(filepath.Join(bundleFolder, key))
			logger.Printf("- Removed embedded.mobileprovision\n")
			continue
		}

		if hashes[i].err != nil {
			return "", fmt.Errorf("hash %s: %w", key, hashes[i].err)
		}
		h1, h256 := hashes[i].h1, hashes[i].h256

		isLproj := strings.Contains(key, ".lproj/")
		isLocVersion := strings.HasSuffix(key, ".lproj/locversion.plist")
		isDS := strings.HasSuffix(key, ".DS_Store") || key == "Info.plist" || key == "PkgInfo"

		if !isLocVersion {
			if isLproj {
				files[key] = map[string]interface{}{
					"hash":     h1,
					"optional": true,
				}
			} else {
				files[key] = h1
			}
		}

		if !isLocVersion && !isDS {
			entry := map[string]interface{}{
				"hash":  h1,
				"hash2": h256,
			}
			if isLproj {
				entry["optional"] = true
			}
			files2[key] = entry
		}
	}

	rules := map[string]interface{}{
		"^.*": true,
		"^.*\\.lproj/": map[string]interface{}{
			"optional": true,
			"weight":   float64(1000),
		},
		"^.*\\.lproj/locversion.plist$": map[string]interface{}{
			"omit":   true,
			"weight": float64(1100),
		},
		"^Base\\.lproj/": map[string]interface{}{
			"weight": float64(1010),
		},
		"^version.plist$": true,
	}

	rules2 := map[string]interface{}{
		"^.*": true,
		".*\\.dSYM($|/)": map[string]interface{}{
			"weight": float64(11),
		},
		"^(.*/)?\\.DS_Store$": map[string]interface{}{
			"omit":   true,
			"weight": float64(2000),
		},
		"^.*\\.lproj/": map[string]interface{}{
			"optional": true,
			"weight":   float64(1000),
		},
		"^.*\\.lproj/locversion.plist$": map[string]interface{}{
			"omit":   true,
			"weight": float64(1100),
		},
		"^Base\\.lproj/": map[string]interface{}{
			"weight": float64(1010),
		},
		"^Info\\.plist$": map[string]interface{}{
			"omit":   true,
			"weight": float64(20),
		},
		"^PkgInfo$": map[string]interface{}{
			"omit":   true,
			"weight": float64(20),
		},
		"^embedded\\.provisionprofile$": map[string]interface{}{
			"weight": float64(20),
		},
		"^version\\.plist$": map[string]interface{}{
			"weight": float64(20),
		},
	}

	cr := map[string]interface{}{
		"files":  files,
		"files2": files2,
		"rules":  rules,
		"rules2": rules2,
	}

	out, err := plist.Marshal(cr, plist.XMLFormat)
	if err != nil {
		return "", fmt.Errorf("marshal CodeResources: %w", err)
	}
	return string(out), nil
}

func updateCodeResources(existing []byte, appFolder, nodePath string, changed []string) (string, error) {
	var cr map[string]interface{}
	if _, err := plist.Unmarshal(existing, &cr); err != nil {
		return "", fmt.Errorf("unmarshal CodeResources: %w", err)
	}

	filesRaw := cr["files"]
	files2Raw := cr["files2"]
	filesMap, _ := filesRaw.(map[string]interface{})
	files2Map, _ := files2Raw.(map[string]interface{})

	for _, relToApp := range changed {
		absPath := filepath.Join(appFolder, filepath.FromSlash(relToApp))
		h1, h256, err := fileHashes(absPath)
		if err != nil {
			return "", fmt.Errorf("hash changed file %s: %w", relToApp, err)
		}

		key := relToApp
		if nodePath != "/" {
			key = strings.TrimPrefix(relToApp, nodePath+"/")
		}
		key = filepath.ToSlash(key)

		if filesMap != nil {
			if existing, ok := filesMap[key]; ok {
				if _, isDict := existing.(map[string]interface{}); isDict {
					filesMap[key] = map[string]interface{}{
						"hash":     h1,
						"optional": true,
					}
				} else {
					filesMap[key] = h1
				}
			}
		}

		if files2Map != nil {
			if entry, ok := files2Map[key].(map[string]interface{}); ok {
				entry["hash"] = h1
				entry["hash2"] = h256
			}
		}
	}

	if filesMap != nil {
		cr["files"] = filesMap
	}
	if files2Map != nil {
		cr["files2"] = files2Map
	}

	out, err := plist.Marshal(cr, plist.XMLFormat)
	if err != nil {
		return "", fmt.Errorf("marshal updated CodeResources: %w", err)
	}
	return string(out), nil
}
