package certcheck

import (
	"archive/zip"
	"bytes"
	"crypto"
	_ "crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.mozilla.org/pkcs7"
	"golang.org/x/crypto/ocsp"
	"howett.net/plist"
	"software.sslmate.com/src/go-pkcs12"

	"github.com/forgiverina/askua/pkg/cert"
	"github.com/forgiverina/askua/pkg/codesign"
	"github.com/forgiverina/askua/pkg/logger"
)

type fileKind int

const (
	kindUnknown fileKind = iota
	kindProvision
	kindP12
	kindCER
	kindPEM
	kindIPA
	kindMachO
)

func CheckFile(path, password string) error {
	header := make([]byte, 8)
	if f, err := os.Open(path); err == nil {
		n, _ := f.Read(header)
		f.Close()
		header = header[:n]
	}

	kind := detectKind(path, header)
	if kind == kindUnknown {
		return fmt.Errorf("unrecognised file type: %s", path)
	}

	kindName := kindNames[kind]
	logger.Printf("\n- Check:\t%s (%s)\n", path, kindName)

	isSigned := false
	showSigned := kind == kindIPA || kind == kindMachO
	var c *x509.Certificate

	switch kind {
	case kindProvision, kindP12, kindCER, kindPEM, kindMachO:
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		switch kind {
		case kindProvision:
			c = certFromProvision(data)
		case kindP12:
			if c, err = certFromP12(data, password); err != nil {
				return err
			}
		case kindCER, kindPEM:
			c = parseCert(data)
		case kindMachO:
			isSigned, c = certFromMachOBytes(data)
		}
	case kindIPA:
		isSigned, c = certFromIPA(path)
	}

	if showSigned && !isSigned {
		logger.Printf("- Signed:\tNo\n\n")
		return nil
	}
	if showSigned {
		logger.Printf("- Signed:\tYes\n")
	}

	if c == nil {
		return fmt.Errorf("could not load certificate from %s", path)
	}

	printCertInfo(c)

	issuer := resolveIssuer(c)
	if issuer == nil {
		logger.Printf("- OCSP:\tSkipped (non-WWDR issuer)\n\n")
		return checkExpiry(c)
	}

	status, revokedAt, detail := performOCSP(c, issuer)
	printOCSPResult(status, revokedAt, detail)
	logger.Printf("\n")

	if status == "Revoked" {
		return fmt.Errorf("certificate has been revoked (at %s)", revokedAt)
	}
	return checkExpiry(c)
}

var kindNames = map[fileKind]string{
	kindProvision: "Provision",
	kindP12:       "PKCS#12",
	kindCER:       "DER",
	kindPEM:       "PEM",
	kindIPA:       "IPA",
	kindMachO:     "Mach-O",
}

func detectKind(path string, data []byte) fileKind {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".mobileprovision", ".provisionprofile":
		return kindProvision
	case ".p12", ".pfx":
		return kindP12
	case ".cer", ".der", ".crt":
		return kindCER
	case ".pem":
		return kindPEM
	case ".ipa", ".zip":
		return kindIPA
	}

	if len(data) < 4 {
		return kindUnknown
	}
	magic := binary.BigEndian.Uint32(data[:4])
	switch magic {
	case 0x504b0304:
		return kindIPA
	case 0xfeedface, 0xcefaedfe, 0xfeedfacf, 0xcffaedfe, 0xcafebabe, 0xbebafeca:
		return kindMachO
	}
	if bytes.HasPrefix(data, []byte("-----BEGIN")) {
		return kindPEM
	}
	if bytes.Contains(data, []byte("<?xml")) && bytes.Contains(data, []byte("</plist>")) {
		return kindProvision
	}
	if len(data) > 4 && data[0] == 0x30 {
		if len(data) > 500 {
			return kindP12
		}
		return kindCER
	}
	return kindUnknown
}

func certFromProvision(data []byte) *x509.Certificate {
	p7, err := pkcs7.Parse(data)
	var content []byte
	if err != nil {
		if idx := bytes.Index(data, []byte("<?xml")); idx >= 0 {
			content = data[idx:]
		} else {
			return nil
		}
	} else {
		content = p7.Content
	}

	var info map[string]interface{}
	if _, err := plist.Unmarshal(content, &info); err != nil {
		return nil
	}
	devCerts, ok := info["DeveloperCertificates"].([]interface{})
	if !ok || len(devCerts) == 0 {
		return nil
	}
	for _, dc := range devCerts {
		raw, ok := dc.([]byte)
		if !ok {
			continue
		}
		if c, err := x509.ParseCertificate(raw); err == nil {
			return c
		}
	}
	return nil
}

func certFromP12(data []byte, password string) (*x509.Certificate, error) {
	_, c, _, err := pkcs12.DecodeChain(data, password)
	if errors.Is(err, pkcs12.ErrIncorrectPassword) {
		return nil, fmt.Errorf("incorrect password for PKCS#12 file (use -p)")
	}
	return c, err
}

func parseCert(data []byte) *x509.Certificate {
	if block, _ := pem.Decode(data); block != nil {
		if c, err := x509.ParseCertificate(block.Bytes); err == nil {
			return c
		}
	}
	if c, err := x509.ParseCertificate(data); err == nil {
		return c
	}
	return nil
}

func certFromMachOBytes(data []byte) (signed bool, c *x509.Certificate) {
	if len(data) < 4 {
		return false, nil
	}
	magic := binary.BigEndian.Uint32(data[:4])

	type archSlice struct{ off, size uint32 }
	var arches []archSlice

	switch magic {
	case 0xcafebabe, 0xbebafeca: // FAT
		if len(data) < 8 {
			return false, nil
		}
		n := int(binary.BigEndian.Uint32(data[4:8]))
		for i := 0; i < n; i++ {
			base := 8 + i*20
			if base+20 > len(data) {
				break
			}
			off := binary.BigEndian.Uint32(data[base+8:])
			size := binary.BigEndian.Uint32(data[base+12:])
			arches = append(arches, archSlice{off, size})
		}
	default:
		arches = []archSlice{{0, uint32(len(data))}}
	}

	for _, a := range arches {
		end := int(a.off) + int(a.size)
		if end > len(data) {
			continue
		}
		slice := data[a.off:end]
		s, cert := certFromSingleArch(slice)
		if s {
			signed = true
		}
		if cert != nil {
			return true, cert
		}
	}
	return signed, nil
}

func certFromSingleArch(data []byte) (signed bool, c *x509.Certificate) {
	if len(data) < 28 {
		return false, nil
	}
	magic := binary.BigEndian.Uint32(data[:4])

	var isBigEndian bool
	var headerSize uint32
	switch magic {
	case 0xfeedface:
		isBigEndian, headerSize = false, 28
	case 0xcefaedfe:
		isBigEndian, headerSize = true, 28
	case 0xfeedfacf:
		isBigEndian, headerSize = false, 32
	case 0xcffaedfe:
		isBigEndian, headerSize = true, 32
	default:
		return false, nil
	}

	read32 := func(off int) uint32 {
		v := binary.BigEndian.Uint32(data[off:])
		if isBigEndian {
			return v>>24 | (v>>8)&0xff00 | (v<<8)&0xff0000 | v<<24
		}
		return v
	}

	ncmds := read32(16)
	off := int(headerSize)
	for i := uint32(0); i < ncmds; i++ {
		if off+8 > len(data) {
			break
		}
		cmd := read32(off)
		cmdSize := int(read32(off + 4))
		if cmd == 0x1d { // LC_CODE_SIGNATURE
			if off+16 > len(data) {
				break
			}
			sigOff := int(read32(off + 8))
			sigLen := int(read32(off + 12))
			signed = sigOff > 0 && sigLen > 0
			if !signed {
				break
			}
			end := sigOff + sigLen
			if end > len(data) {
				break
			}
			c = codesign.SigningCert(data[sigOff:end])
			return signed, c
		}
		off += cmdSize
		if cmdSize < 8 {
			break
		}
	}
	return false, nil
}

func certFromIPA(ipaPath string) (signed bool, c *x509.Certificate) {
	r, err := zip.OpenReader(ipaPath)
	if err != nil {
		return false, nil
	}
	defer r.Close()

	var appPrefix, execName string
	for _, f := range r.File {
		parts := strings.Split(f.Name, "/")
		if len(parts) == 3 && parts[0] == "Payload" &&
			strings.HasSuffix(parts[1], ".app") && parts[2] == "Info.plist" {
			rc, err := f.Open()
			if err != nil {
				break
			}
			data, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				break
			}
			var info map[string]interface{}
			if _, err := plist.Unmarshal(data, &info); err != nil {
				break
			}
			if v, ok := info["CFBundleExecutable"].(string); ok {
				execName = v
				appPrefix = parts[0] + "/" + parts[1] + "/"
			}
			break
		}
	}
	if execName == "" {
		return false, nil
	}

	execPath := appPrefix + execName
	for _, f := range r.File {
		if f.Name != execPath {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			break
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			break
		}
		return certFromMachOBytes(data)
	}
	return false, nil
}

func resolveIssuer(c *x509.Certificate) *x509.Certificate {
	for _, pemStr := range []string{cert.AppleDevCACertG3, cert.AppleDevCACert} {
		block, _ := pem.Decode([]byte(pemStr))
		if block == nil {
			continue
		}
		ca, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		if c.Issuer.String() != ca.Subject.String() {
			continue
		}
		if err := c.CheckSignatureFrom(ca); err == nil {
			return ca
		}
	}
	return nil
}

func performOCSP(leaf, issuer *x509.Certificate) (status, revokedAt, detail string) {
	ocspURL := ocspURLFromCert(leaf)
	if ocspURL == "" {
		ocspURL = "http://ocsp.apple.com/ocsp03-wwdrg3"
		for _, suffix := range []string{"G6", "G3", "G2"} {
			if strings.Contains(issuer.Subject.CommonName, suffix) {
				ocspURL = "http://ocsp.apple.com/ocsp03-wwdrg" + strings.ToLower(suffix)
				break
			}
		}
	}

	req, err := ocsp.CreateRequest(leaf, issuer, &ocsp.RequestOptions{Hash: crypto.SHA1})
	if err != nil {
		return "Error", "", fmt.Sprintf("build request: %v", err)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Post(ocspURL, "application/ocsp-request", bytes.NewReader(req)) //nolint:noctx
	if err != nil {
		return "Error", "", fmt.Sprintf("HTTP POST: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "Error", "", fmt.Sprintf("read response: %v", err)
	}

	parsed, err := ocsp.ParseResponseForCert(body, leaf, issuer)
	if err != nil {
		return "Error", "", fmt.Sprintf("parse response: %v", err)
	}

	switch parsed.Status {
	case ocsp.Good:
		return "Valid", "", ""
	case ocsp.Revoked:
		return "Revoked", parsed.RevokedAt.UTC().Format(time.RFC3339), ""
	default:
		return "Unknown", "", ""
	}
}

func ocspURLFromCert(c *x509.Certificate) string {
	for _, u := range c.OCSPServer {
		if strings.HasPrefix(u, "http") {
			return u
		}
	}
	return ""
}

func printCertInfo(c *x509.Certificate) {
	cn := c.Subject.CommonName
	org := ""
	if len(c.Subject.Organization) > 0 {
		org = c.Subject.Organization[0]
	}
	ou := ""
	if len(c.Subject.OrganizationalUnit) > 0 {
		ou = c.Subject.OrganizationalUnit[0]
	}
	issuerCN := c.Issuer.CommonName
	serial := formatSerial(c.SerialNumber)
	algo := keyAlgoName(c)
	certType := detectCertType(cn)
	daysLeft := int(time.Until(c.NotAfter).Hours() / 24)

	logger.Printf("- Name:\t%s\n", cn)
	logger.Printf("- Type:\t%s\n", certType)
	if org != "" {
		logger.Printf("- Org:\t%s\n", org)
	}
	if ou != "" {
		logger.Printf("- Team:\t%s\n", ou)
	}
	logger.Printf("- Serial:\t%s\n", serial)
	logger.Printf("- Issued:\t%s\n", c.NotBefore.UTC().Format(time.RFC3339))

	expires := c.NotAfter.UTC().Format(time.RFC3339)
	switch {
	case daysLeft < 0:
		logger.Errorf("- Expires:\t%s (EXPIRED %d days ago)\n", expires, -daysLeft)
	case daysLeft < 30:
		logger.Warnf("- Expires:\t%s (%d days remaining!)\n", expires, daysLeft)
	default:
		logger.Successf("- Expires:\t%s (%d days remaining)\n", expires, daysLeft)
	}

	logger.Printf("- Algorithm:\t%s\n", algo)
	logger.Printf("- Issuer:\t%s\n", issuerCN)
}

func printOCSPResult(status, revokedAt, detail string) {
	switch status {
	case "Valid":
		logger.Success("- OCSP:\tValid (ocsp.apple.com)\n")
	case "Revoked":
		logger.Error("- OCSP:\tRevoked\n")
		if revokedAt != "" {
			logger.Errorf("- Revoked:\t%s\n", revokedAt)
		}
	case "Unknown":
		logger.Warn("- OCSP:\tUnknown\n")
	default:
		logger.Warn("- OCSP:\tError\n")
	}
	if detail != "" {
		logger.Printf("- Detail:\t%s\n", detail)
	}
}

func checkExpiry(c *x509.Certificate) error {
	if time.Now().After(c.NotAfter) {
		return fmt.Errorf("certificate expired on %s", c.NotAfter.UTC().Format(time.RFC3339))
	}
	return nil
}

func formatSerial(n *big.Int) string {
	raw := hex.EncodeToString(n.Bytes())
	var b strings.Builder
	for i, ch := range raw {
		if i > 0 && i%2 == 0 {
			b.WriteByte(':')
		}
		b.WriteRune(ch)
	}
	return b.String()
}

func keyAlgoName(c *x509.Certificate) string {
	switch c.PublicKeyAlgorithm {
	case x509.RSA:
		if k, ok := c.PublicKey.(interface{ Size() int }); ok {
			return fmt.Sprintf("RSA %d-bit", k.Size()*8)
		}
		return "RSA"
	case x509.ECDSA:
		return "EC"
	case x509.Ed25519:
		return "Ed25519"
	default:
		return c.PublicKeyAlgorithm.String()
	}
}

func detectCertType(cn string) string {
	for _, prefix := range []string{
		"Apple Distribution", "iPhone Distribution",
		"Apple Development", "iPhone Developer",
		"Mac Developer", "Developer ID Application",
		"Developer ID Installer",
	} {
		if strings.Contains(cn, prefix) {
			return prefix
		}
	}
	return "Certificate"
}
