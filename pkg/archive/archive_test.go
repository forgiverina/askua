package archive

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestIsPathSafe(t *testing.T) {
	for name, want := range map[string]bool{
		"Payload/":                   true,
		"Payload/App.app/Info.plist": true,
		"":                           false,
		"/etc/passwd":                false,
		"../evil":                    false,
		"Payload/../../evil":         false,
		`Payload\..\..\evil`:         false,
	} {
		if got := isPathSafe(name); got != want {
			t.Errorf("isPathSafe(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestArchiveExtractRoundTrip(t *testing.T) {
	src := t.TempDir()
	app := filepath.Join(src, "Payload", "App.app")
	if err := os.MkdirAll(app, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "App"), []byte("binary"), 0o555); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Symlink("App", filepath.Join(app, "link")); err != nil {
			t.Fatal(err)
		}
	}

	for _, level := range []int{0, 6} {
		ipa := filepath.Join(t.TempDir(), "out.ipa")
		if err := Archive(src, ipa, level); err != nil {
			t.Fatalf("Archive(level %d): %v", level, err)
		}
		if !IsZipFile(ipa) {
			t.Fatal("output is not a zip")
		}
		dst := filepath.Join(t.TempDir(), "x")
		if err := Extract(ipa, dst); err != nil {
			t.Fatalf("Extract: %v", err)
		}
		exe := filepath.Join(dst, "Payload", "App.app", "App")
		data, err := os.ReadFile(exe)
		if err != nil || string(data) != "binary" {
			t.Fatalf("round-trip content = %q, %v", data, err)
		}
		if fi, _ := os.Stat(exe); fi.Mode().Perm()&0o200 == 0 {
			t.Errorf("extracted file is not owner-writable: %v", fi.Mode())
		}
		if runtime.GOOS != "windows" {
			if target, err := os.Readlink(filepath.Join(dst, "Payload", "App.app", "link")); err != nil || target != "App" {
				t.Errorf("symlink not preserved: %q, %v", target, err)
			}
		}
	}
}
