package codesign

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/forgiverina/askua/pkg/cert"
	"howett.net/plist"
)

var (
	oidCDHashesPlist = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 9, 1}
	oidCDHashes2     = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 9, 2}
	oidSHA256        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA1          = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26} //nolint:unused
	oidData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidRSA           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
)

func BuildCMSSignature(asset *cert.Asset, cdSlot1, cdSlot256 []byte) ([]byte, error) {
	if asset.Adhoc {
		return []byte{0xfa, 0xde, 0x0b, 0x01, 0x00, 0x00, 0x00, 0x08}, nil
	}

	cmsData, err := buildCMS(asset, cdSlot1, cdSlot256)
	if err != nil {
		return nil, err
	}

	var out bytes.Buffer
	binary.Write(&out, binary.BigEndian, uint32(0xfade0b01))     //nolint:errcheck
	binary.Write(&out, binary.BigEndian, uint32(len(cmsData)+8)) //nolint:errcheck
	out.Write(cmsData)
	return out.Bytes(), nil
}

func buildCMS(asset *cert.Asset, cdSlot1, cdSlot256 []byte) ([]byte, error) {
	signingCert := asset.Cert
	privKey := asset.PrivKey

	if signingCert == nil || privKey == nil {
		return nil, fmt.Errorf("cert or key not loaded")
	}

	intermedPEM := cert.AppleDevCACertG3
	intermedCert, err := parsePEMCert(intermedPEM)
	if err != nil {
		intermedCert, err = parsePEMCert(cert.AppleDevCACert)
		if err != nil {
			return nil, fmt.Errorf("load Apple intermediate CA: %w", err)
		}
	}
	rootCert, _ := parsePEMCert(cert.AppleRootCACert)

	content := cdSlot1

	var cdHashesPlistData []byte
	if len(cdSlot1) > 0 && len(cdSlot256) > 0 {
		sha1OfCD1 := sha1.Sum(cdSlot1) //nolint:gosec
		sha256OfCD256 := sha256.Sum256(cdSlot256)

		plistMap := map[string]interface{}{
			"cdhashes": []interface{}{
				sha1OfCD1[:],
				sha256OfCD256[:20],
			},
		}
		cdHashesPlistData, err = plist.MarshalIndent(plistMap, plist.XMLFormat, "\t")
		if err != nil {
			return nil, fmt.Errorf("marshal CDHashes plist: %w", err)
		}
	}

	sha256HexOfCD256 := ""
	if len(cdSlot256) > 0 {
		sum := sha256.Sum256(cdSlot256)
		sha256HexOfCD256 = strings.ToUpper(hex.EncodeToString(sum[:]))
	}

	digest := sha256.Sum256(content)
	now := time.Now()

	signedAttrsRaw, err := buildSignedAttrs(oidData, now, digest[:], cdHashesPlistData, sha256HexOfCD256)
	if err != nil {
		return nil, fmt.Errorf("build signed attrs: %w", err)
	}

	toSign := make([]byte, len(signedAttrsRaw))
	copy(toSign, signedAttrsRaw)
	toSign[0] = 0x31 // Change SEQUENCE to SET for signing
	hashToSign := sha256.Sum256(toSign)

	rsaKey, ok := privKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("only RSA keys are supported")
	}

	sig, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, hashToSign[:])
	if err != nil {
		return nil, fmt.Errorf("RSA sign: %w", err)
	}

	signerInfo, err := buildSignerInfo(signingCert, signedAttrsRaw, sig)
	if err != nil {
		return nil, fmt.Errorf("build SignerInfo: %w", err)
	}

	var certs [][]byte
	certs = append(certs, signingCert.Raw)
	if intermedCert != nil {
		certs = append(certs, intermedCert.Raw)
	}
	if rootCert != nil {
		certs = append(certs, rootCert.Raw)
	}

	signedData, err := buildSignedData(certs, signerInfo)
	if err != nil {
		return nil, fmt.Errorf("build SignedData: %w", err)
	}

	contentInfo, err := buildContentInfo(signedData)
	if err != nil {
		return nil, fmt.Errorf("build ContentInfo: %w", err)
	}

	return contentInfo, nil
}

type pkcs7Attribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue
}

func buildSignedAttrs(contentType asn1.ObjectIdentifier, signingTime time.Time, digest, cdHashesPlist []byte, sha256Hex string) ([]byte, error) {
	var attrs []pkcs7Attribute

	ctVal, _ := asn1.Marshal(contentType)
	attrs = append(attrs, pkcs7Attribute{
		Type:   oidContentType,
		Values: []asn1.RawValue{{FullBytes: ctVal}},
	})

	stVal, _ := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal,
		Tag:   23, // UTCTime
		Bytes: []byte(signingTime.UTC().Format("060102150405Z")),
	})
	attrs = append(attrs, pkcs7Attribute{
		Type:   oidSigningTime,
		Values: []asn1.RawValue{{FullBytes: stVal}},
	})

	mdVal, _ := asn1.Marshal(digest)
	attrs = append(attrs, pkcs7Attribute{
		Type:   oidMessageDigest,
		Values: []asn1.RawValue{{FullBytes: mdVal}},
	})

	if len(cdHashesPlist) > 0 {
		plistVal, _ := asn1.Marshal(cdHashesPlist)
		attrs = append(attrs, pkcs7Attribute{
			Type:   oidCDHashesPlist,
			Values: []asn1.RawValue{{FullBytes: plistVal}},
		})
	}

	if sha256Hex != "" {
		hashBytes, _ := hex.DecodeString(sha256Hex)
		innerSeq, _ := asn1.Marshal(struct {
			OID  asn1.ObjectIdentifier
			Hash []byte
		}{oidSHA256, hashBytes})
		attrs = append(attrs, pkcs7Attribute{
			Type:   oidCDHashes2,
			Values: []asn1.RawValue{{FullBytes: innerSeq}},
		})
	}

	var seqBytes []byte
	for _, a := range attrs {
		b, err := marshalAttribute(a)
		if err != nil {
			return nil, err
		}
		seqBytes = append(seqBytes, b...)
	}

	seq := asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      seqBytes,
	}
	return asn1.Marshal(seq)
}

func marshalAttribute(a pkcs7Attribute) ([]byte, error) {
	var vals []byte
	for _, v := range a.Values {
		b, err := asn1.Marshal(v)
		if err != nil {
			return nil, err
		}
		vals = append(vals, b...)
	}
	setVal := asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      vals,
	}
	setBytes, _ := asn1.Marshal(setVal)
	oidBytes, _ := asn1.Marshal(a.Type)

	seqBytes := append(oidBytes, setBytes...)
	seq := asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      seqBytes,
	}
	return asn1.Marshal(seq)
}

func buildSignerInfo(sigCert *x509.Certificate, signedAttrs, signature []byte) ([]byte, error) {
	issuerRaw := asn1.RawValue{FullBytes: sigCert.RawIssuer}
	serial := new(big.Int).Set(sigCert.SerialNumber)
	iasn, err := asn1.Marshal(struct {
		Issuer asn1.RawValue
		Serial *big.Int
	}{issuerRaw, serial})
	if err != nil {
		return nil, err
	}

	sha256AlgID, _ := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: oidSHA256})
	rsaAlgID, _ := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: oidRSA})
	sigBytes, _ := asn1.Marshal(signature)

	signedAttrsTagged := make([]byte, len(signedAttrs))
	copy(signedAttrsTagged, signedAttrs)
	signedAttrsTagged[0] = 0xa0 // [0] CONSTRUCTED IMPLICIT

	versionBytes, _ := asn1.Marshal(1)

	inner := concat(versionBytes, iasn, sha256AlgID, signedAttrsTagged, rsaAlgID, sigBytes)
	return marshalSEQUENCE(inner), nil
}

func buildSignedData(certs [][]byte, signerInfo []byte) ([]byte, error) {
	sha256AlgID, _ := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: oidSHA256})
	digestAlgs := marshalSET(sha256AlgID)

	contentTypeBytes, _ := asn1.Marshal(oidData)
	encapCI := marshalSEQUENCE(contentTypeBytes)

	var allCerts []byte
	for _, c := range certs {
		allCerts = append(allCerts, c...)
	}
	certsTagged := marshalTagged(0, allCerts)

	signerInfos := marshalSET(signerInfo)

	versionBytes, _ := asn1.Marshal(1)
	inner := concat(versionBytes, digestAlgs, encapCI, certsTagged, signerInfos)
	return marshalSEQUENCE(inner), nil
}

func buildContentInfo(signedData []byte) ([]byte, error) {
	oidBytes, _ := asn1.Marshal(oidSignedData)
	contentTagged := marshalTagged(0, signedData)
	inner := concat(oidBytes, contentTagged)
	return marshalSEQUENCE(inner), nil
}

func marshalSEQUENCE(inner []byte) []byte {
	r := asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: inner}
	b, _ := asn1.Marshal(r)
	return b
}

func marshalSET(inner []byte) []byte {
	r := asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: inner}
	b, _ := asn1.Marshal(r)
	return b
}

func marshalTagged(tag int, inner []byte) []byte {
	r := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, IsCompound: true, Bytes: inner}
	b, _ := asn1.Marshal(r)
	return b
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func parsePEMCert(pemData string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	return x509.ParseCertificate(block.Bytes)
}
