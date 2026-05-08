# Askua

iOS code signing for macOS, Linux, and Windows — no Xcode required
Sign IPA files, inject or remove dylibs, and check certificate validity in Go
made to embed directly in iOS apps via gomobile or run as a standalone CLI

based on [zsign](https://github.com/zhlynn/zsign)

---

## Contents

- [CLI](#cli)
  - [Install](#install)
  - [Usage](#usage)
  - [Flags](#flags)
  - [Examples](#examples)
- [App Integration (gomobile)](#app-integration-gomobile)
  - [Build the framework](#build-the-framework)
  - [Add to Xcode](#add-to-xcode)
  - [Swift API](#swift-api)
- [Package layout](#package-layout)
- [Requirements](#requirements)

---

## CLI

### Install

```bash
go install github.com/forgiverina/askua/cmd/askua@latest
```

Or build from source:

```bash
git clone https://github.com/forgiverina/askua
cd askua
go build -o askua ./cmd/askua
```

### Usage

```
askua [flags] <file|folder>
```

`<file|folder>` can be:

| Input | Behaviour |
|-------|-----------|
| `App.ipa` | Extract, sign, repack to `-o output.ipa` |
| `App.app/` | Sign the folder in place |
| `MyFramework` | Sign a bare Mach-O binary |
| `cert.p12` / `profile.mobileprovision` | Inspect with `-C` |

### Flags

**Credentials**

| Flag | Short | Description |
|------|-------|-------------|
| `--cert` | `-c` | Certificate file (PEM or DER) |
| `--pkey` | `-k` | Private key or `.p12` file |
| `--prov` | `-m` | Provisioning profile (repeatable for multi-profile) |
| `--password` | `-p` | Password for p12 / encrypted key |
| `--entitlements` | `-e` | Custom entitlements plist |
| `--adhoc` | `-a` | Ad-hoc sign (no cert or profile needed) |

**Output**

| Flag | Short | Description |
|------|-------|-------------|
| `--output` | `-o` | Destination IPA path |
| `--temp_folder` | `-t` | Working directory (default: system temp) |
| `--metadata` | `-x` | Write `metadata.json` + icon to this directory |
| `--zip_level` | `-z` | ZIP compression 0–9 (default 0 = store) |

**Identity overrides**

| Flag | Short | Description |
|------|-------|-------------|
| `--bundle_id` | `-b` | Override `CFBundleIdentifier` |
| `--bundle_name` | `-n` | Override `CFBundleDisplayName` |
| `--bundle_version` | `-r` | Override `CFBundleVersion` |
| `--min_version` | `-M` | Override `MinimumOSVersion` |

**Dylib management**

| Flag | Short | Description |
|------|-------|-------------|
| `--dylib` | `-l` | Inject a dylib (repeatable) |
| `--rm_dylib` | `-D` | Remove a dylib by name (repeatable) |
| `--weak` | `-w` | Inject as `LC_LOAD_WEAK_DYLIB` |

**Behaviour**

| Flag | Short | Description |
|------|-------|-------------|
| `--force` | `-f` | Re-sign even if signature is cached |
| `--check` | `-C` | Check cert/OCSP validity and exit |
| `--sha256_only` | `-2` | Single SHA-256 CodeDirectory (skip SHA-1) |
| `--install` | `-i` | Install signed IPA via `ideviceinstaller` |
| `--rm_provision` | `-R` | Strip `embedded.mobileprovision` after signing |
| `--enable_docs` | `-S` | Enable document browser + file sharing |
| `--rm_extensions` | `-E` | Remove all app extensions |
| `--rm_watch` | `-W` | Remove embedded Watch app |
| `--rm_uisd` | `-U` | Remove `UISupportedDevices` |
| `--verbose` | `-V` | Debug logging |
| `--quiet` | `-q` | Suppress non-error output |

### Examples

```bash
# Sign an IPA with a p12 and provisioning profile
askua -k dev.p12 -p secret -m dev.mobileprovision -o signed.ipa App.ipa

# Ad-hoc sign a bare binary
askua -a -o MyApp.signed MyApp

# Re-sign with a new bundle ID and inject a tweak dylib
askua -k dev.p12 -m dev.mobileprovision \
      -b com.myorg.myapp \
      -l Tweak.dylib \
      -o patched.ipa App.ipa

# Check certificate and OCSP status
askua -C dev.p12 -p secret

# Strip Watch app and extensions, then install on device
askua -k dev.p12 -m dev.mobileprovision -W -E -i -o out.ipa App.ipa
```

---

## App Integration (gomobile)

Askua ships `pkg/mobile` — a thin, gomobile-compatible wrapper that exposes signing as a single function call. This is what you link into your iOS app for on-device signing.

### Build the framework

**Prerequisites**

```bash
go install golang.org/x/mobile/cmd/gomobile@latest
gomobile init
```

**Build**

```bash
gomobile bind \
  -target ios \
  -o Askua.xcframework \
  github.com/forgiverina/askua/pkg/mobile
```

This produces `Askua.xcframework` ready to drop into Xcode.

> Add `-ldflags "-s -w"` to strip debug symbols and shrink the binary.

### Add to Xcode

1. Drag `Askua.xcframework` into your Xcode project.
2. In **Target → General → Frameworks, Libraries, and Embedded Content** set it to **Embed & Sign**.
3. Import the module: `import Mobile`

### Swift API

```swift
import Mobile

// Sign an IPA
let opts = MobileSignOptions()
opts.keyPath    = Bundle.main.path(forResource: "dev", ofType: "p12")!
opts.password   = "secret"
opts.provPath   = Bundle.main.path(forResource: "dev", ofType: "mobileprovision")!
opts.outputPath = NSTemporaryDirectory() + "signed.ipa"
opts.zipLevel   = 0

let result = MobileSign("/path/to/App.ipa", opts)
if result.success {
    print("Done in \(result.elapsed)ms")
} else {
    print("Failed: \(result.error_)")
}

// Ad-hoc sign a bare Mach-O
let adhoc = MobileSignOptions()
adhoc.adhoc = true
MobileSign("/path/to/binary", adhoc)

// Check whether a binary is already signed
let isSigned = MobileCheckSignature("/path/to/binary")

// Extract metadata.json + app icon
let err = MobileExtractMetadata("/path/to/App.app", "/output/dir")

// Control logging (0=none, 1=info, 2=debug)
MobileSetLogLevel(0)
```

**SignOptions**

| Field | Type | Description |
|-------|------|-------------|
| `CertPath` | `String` | Path to `.pem` or `.cer` certificate |
| `KeyPath` | `String` | Path to `.pem` or `.p12` private key |
| `ProvPath` | `String` | Path to `.mobileprovision` |
| `Password` | `String` | p12 / key passphrase |
| `BundleID` | `String` | Override bundle identifier |
| `BundleName` | `String` | Override display name |
| `BundleVersion` | `String` | Override version string |
| `Adhoc` | `Bool` | Ad-hoc sign (no cert needed) |
| `ForceResign` | `Bool` | Ignore signature cache |
| `WeakDylib` | `Bool` | Inject dylibs as `LC_LOAD_WEAK_DYLIB` |
| `ZipLevel` | `Int` | Output IPA compression 0–9 |
| `TempDir` | `String` | Scratch directory (default: system temp) |
| `OutputPath` | `String` | Destination IPA path |
| `MetadataDir` | `String` | Write `metadata.json` + icon here |
| `EnableDocuments` | `Bool` | Enable document browser / file sharing |
| `RemoveExtensions` | `Bool` | Strip PlugIns / Extensions |
| `RemoveWatchApp` | `Bool` | Strip embedded Watch app |
| `MinVersion` | `String` | Override `MinimumOSVersion` |

**SignResult**

| Field | Type | Description |
|-------|------|-------------|
| `Success` | `Bool` | Whether signing succeeded |
| `Error` | `String` | Error message when `Success == false` |
| `Elapsed` | `Int64` | Wall time in milliseconds |

---

## Package layout

```
cmd/askua/          CLI entry point
pkg/mobile/         gomobile API (start here for app integration)
pkg/bundle/         IPA bundle signing orchestration
pkg/macho/          Mach-O parser and signer
pkg/codesign/       CodeDirectory, CMS, Requirements, Entitlements builders
pkg/cert/           Certificate, key, and provisioning profile loading
pkg/certcheck/      OCSP revocation and signature inspection
pkg/archive/        ZIP extraction and IPA repacking
pkg/metadata/       App metadata and icon extraction
pkg/logger/         Levelled logging
```

---

## Requirements

- Go 1.21+
- gomobile (only for iOS framework builds)
- `ideviceinstaller` (not needed, only for `--install` / `-i`)
