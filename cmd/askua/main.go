package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func main() {
	if err := rootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	var opts runOpts

	cmd := &cobra.Command{
		Use:   "askua [flags] <file|folder>",
		Short: "askua — iOS code signing for macOS, Linux and Windows",
		Long: fmt.Sprintf(
			"askua — codesign alternative for iOS 12+ running on macOS, Linux and Windows.\n" +
				"See https://github.com/forgiverina/askua for details.",
		),
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(args[0], opts)
		},
	}

	f := cmd.Flags()
	f.BoolVarP(&opts.debug, "debug", "d", false, "Generate debug output files (.askua_debug folder)")
	f.BoolVarP(&opts.force, "force", "f", false, "Force sign without cache")
	f.BoolVarP(&opts.verbose, "verbose", "V", false, "Verbose output (enable debug logging)")
	f.BoolVarP(&opts.adhoc, "adhoc", "a", false, "Perform ad-hoc signature only")
	f.BoolVarP(&opts.sha256Only, "sha256_only", "2", false, "Use a single SHA256 CodeDirectory only")
	f.BoolVarP(&opts.weakInject, "weak", "w", false, "Inject dylib as LC_LOAD_WEAK_DYLIB")
	f.BoolVarP(&opts.install, "install", "i", false, "Install IPA with ideviceinstaller after signing")
	f.BoolVarP(&opts.checkSig, "check", "C", false, "Check certificate validity and OCSP revocation")
	f.BoolVarP(&opts.quiet, "quiet", "q", false, "Quiet mode — suppress non-error output")
	f.BoolVarP(&opts.removeProvision, "rm_provision", "R", false, "Remove embedded.mobileprovision after signing")
	f.BoolVarP(&opts.enableDocs, "enable_docs", "S", false, "Enable UISupportsDocumentBrowser and UIFileSharingEnabled")
	f.BoolVarP(&opts.removeExts, "rm_extensions", "E", false, "Remove all app extensions (PlugIns/Extensions)")
	f.BoolVarP(&opts.removeWatch, "rm_watch", "W", false, "Remove Watch app from the bundle")
	f.BoolVarP(&opts.removeUISD, "rm_uisd", "U", false, "Remove UISupportedDevices from Info.plist")

	f.StringVarP(&opts.certFile, "cert", "c", "", "Path to certificate file (PEM or DER)")
	f.StringVarP(&opts.pkeyFile, "pkey", "k", "", "Path to private key or p12 file (PEM or DER)")
	f.StringArrayVarP(&opts.provFiles, "prov", "m", nil, "Path to provisioning profile (repeatable)")
	f.StringVarP(&opts.password, "password", "p", "", "Password for private key or p12 file")
	f.StringVarP(&opts.bundleID, "bundle_id", "b", "", "Override CFBundleIdentifier")
	f.StringVarP(&opts.bundleName, "bundle_name", "n", "", "Override CFBundleDisplayName / CFBundleName")
	f.StringVarP(&opts.bundleVer, "bundle_version", "r", "", "Override CFBundleVersion and CFBundleShortVersionString")
	f.StringVarP(&opts.entitleFile, "entitlements", "e", "", "Path to entitlements plist file")
	f.StringVarP(&opts.outputFile, "output", "o", "", "Output IPA file path")
	f.StringVarP(&opts.tempFolder, "temp_folder", "t", os.TempDir(), "Temporary folder for intermediate files")
	f.StringVarP(&opts.metadataDir, "metadata", "x", "", "Extract app metadata and icon to this directory")
	f.StringVarP(&opts.minVersion, "min_version", "M", "", "Override MinimumOSVersion in Info.plist")
	f.StringVarP(&opts.installerPath, "installer_path", "I", "ideviceinstaller", "Path to ideviceinstaller binary")
	f.IntVarP(&opts.zipLevel, "zip_level", "z", 0, "ZIP compression level (0–9)")
	f.StringArrayVarP(&opts.dylibFiles, "dylib", "l", nil, "Dylib to inject (repeatable)")
	f.StringArrayVarP(&opts.rmDylibs, "rm_dylib", "D", nil, "Dylib name to remove (repeatable)")

	return cmd
}
