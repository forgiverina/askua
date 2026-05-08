package cert

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"go.mozilla.org/pkcs7"
	"howett.net/plist"
	"software.sslmate.com/src/go-pkcs12"
)

type Asset struct {
	Adhoc        bool
	SHA256Only   bool
	SingleBinary bool

	TeamID      string
	SubjectCN   string
	ProvData    []byte
	EntitleData string
	AppID       string

	Cert    *x509.Certificate
	PrivKey crypto.PrivateKey
}

func (a *Asset) Init(certFile, pkeyFile, provFile, entitleFile, password string, adhoc, sha256Only, singleBinary bool) error {
	a.Adhoc = adhoc
	a.SHA256Only = sha256Only
	a.SingleBinary = singleBinary

	if adhoc {
		if entitleFile != "" {
			d, err := os.ReadFile(entitleFile)
			if err != nil {
				return fmt.Errorf("read entitlements: %w", err)
			}
			a.EntitleData = string(d)
		}
		return nil
	}

	provData, err := os.ReadFile(provFile)
	if err != nil {
		return fmt.Errorf("read provisioning profile: %w", err)
	}
	a.ProvData = provData

	provContent, err := extractP7Content(provData)
	if err != nil {
		return fmt.Errorf("parse provisioning profile CMS: %w", err)
	}

	var provInfo map[string]interface{}
	if _, perr := plist.Unmarshal(provContent, &provInfo); perr != nil {
		return fmt.Errorf("unmarshal provisioning plist: %w", perr)
	}
	a.TeamID = firstString(provInfo, "TeamIdentifier")

	if ent, ok := provInfo["Entitlements"].(map[string]interface{}); ok {
		a.AppID = stringVal(ent, "application-identifier")
		if entitleFile == "" {
			buf, merr := plist.MarshalIndent(ent, plist.XMLFormat, "\t")
			if merr == nil {
				a.EntitleData = string(buf)
			}
		}
	}

	if entitleFile != "" {
		d, err := os.ReadFile(entitleFile)
		if err != nil {
			return fmt.Errorf("read entitlements file: %w", err)
		}
		a.EntitleData = string(d)
	}

	if a.TeamID == "" {
		return fmt.Errorf("TeamIdentifier not found in provisioning profile")
	}

	pkeyData, err := os.ReadFile(pkeyFile)
	if err != nil {
		return fmt.Errorf("read private key file: %w", err)
	}

	privKey, embeddedCert, err := loadKeyAndCert(pkeyData, password)
	if err != nil {
		return fmt.Errorf("load private key: %w", err)
	}
	a.PrivKey = privKey

	if embeddedCert != nil && certMatchesKey(embeddedCert, privKey) {
		a.Cert = embeddedCert
	}

	if a.Cert == nil && certFile != "" {
		certData, err := os.ReadFile(certFile)
		if err == nil {
			if c := parseCert(certData); c != nil && certMatchesKey(c, privKey) {
				a.Cert = c
			}
		}
	}

	if a.Cert == nil {
		if devCerts, ok := provInfo["DeveloperCertificates"].([]interface{}); ok {
			for _, dc := range devCerts {
				if raw, ok := dc.([]byte); ok {
					c, err := x509.ParseCertificate(raw)
					if err == nil && certMatchesKey(c, privKey) {
						a.Cert = c
						break
					}
				}
			}
		}
	}

	if a.Cert == nil {
		return fmt.Errorf("could not find a certificate matching the private key")
	}

	a.SubjectCN = a.Cert.Subject.CommonName
	if a.SubjectCN == "" {
		return fmt.Errorf("signing certificate has no Common Name")
	}

	return nil
}

func extractP7Content(data []byte) ([]byte, error) {
	p7, err := pkcs7.Parse(data)
	if err != nil {
		if idx := bytes.Index(data, []byte("<?xml")); idx >= 0 {
			return data[idx:], nil
		}
		if idx := bytes.Index(data, []byte("bplist")); idx >= 0 {
			return data[idx:], nil
		}
		return nil, fmt.Errorf("pkcs7 parse: %w", err)
	}
	return p7.Content, nil
}

func loadKeyAndCert(data []byte, password string) (crypto.PrivateKey, *x509.Certificate, error) {
	if block, _ := pem.Decode(data); block != nil {
		switch block.Type {
		case "RSA PRIVATE KEY":
			k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("parse RSA key: %w", err)
			}
			return k, nil, nil
		case "PRIVATE KEY":
			k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("parse PKCS8 key: %w", err)
			}
			return k, nil, nil
		}
	}

	if k, err := x509.ParsePKCS8PrivateKey(data); err == nil {
		return k, nil, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(data); err == nil {
		return k, nil, nil
	}

	privKey, cert, err := pkcs12.Decode(data, password)
	if err == nil {
		return privKey, cert, nil
	}

	privKey2, cert2, _, err2 := pkcs12.DecodeChain(data, password)
	if err2 == nil {
		return privKey2, cert2, nil
	}

	return nil, nil, fmt.Errorf("unrecognised key format (tried PEM RSA/PKCS8, DER, PKCS12)")
}

func parseCert(data []byte) *x509.Certificate {
	if block, _ := pem.Decode(data); block != nil {
		c, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			return c
		}
	}
	c, err := x509.ParseCertificate(data)
	if err == nil {
		return c
	}
	return nil
}

func certMatchesKey(cert *x509.Certificate, key crypto.PrivateKey) bool {
	switch priv := key.(type) {
	case *rsa.PrivateKey:
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		return ok && priv.PublicKey.N.Cmp(pub.N) == 0 && priv.PublicKey.E == pub.E
	case *ecdsa.PrivateKey:
		pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
		return ok && priv.PublicKey.Equal(pub)
	}
	return false
}

func firstString(m map[string]interface{}, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	switch x := v.(type) {
	case string:
		return x
	case []interface{}:
		if len(x) > 0 {
			if s, ok := x[0].(string); ok {
				return s
			}
		}
	}
	return ""
}

func stringVal(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

const AppleDevCACert = `-----BEGIN CERTIFICATE-----
MIIEIjCCAwqgAwIBAgIIAd68xDltoBAwDQYJKoZIhvcNAQEFBQAwYjELMAkGA1UE
BhMCVVMxEzARBgNVBAoTCkFwcGxlIEluYy4xJjAkBgNVBAsTHUFwcGxlIENlcnRp
ZmljYXRpb24gQXV0aG9yaXR5MRYwFAYDVQQDEw1BcHBsZSBSb290IENBMB4XDTEz
MDIwNzIxNDg0N1oXDTIzMDIwNzIxNDg0N1owgZYxCzAJBgNVBAYTAlVTMRMwEQYD
VQQKDApBcHBsZSBJbmMuMSwwKgYDVQQLDCNBcHBsZSBXb3JsZHdpZGUgRGV2ZWxv
cGVyIFJlbGF0aW9uczFEMEIGA1UEAww7QXBwbGUgV29ybGR3aWRlIERldmVsb3Bl
ciBSZWxhdGlvbnMgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQDKOFSmy1aqyCQ5SOmM7uxfuH8mkbw0U3rOfGOA
YXdkXqUHI7Y5/lAtFVZYcC1+xG7BSoU+L/DehBqhV8mvexj/avoVEkkVCBmsqtsq
Mu2WY2hSFT2Miuy/axiV4AOsAX2XBWfODoWVN2rtCbauZ81RZJ/GXNG8V25nNYB2
NqSHgW44j9grFU57Jdhav06DwY3Sk9UacbVgnJ0zTlX5ElgMhrgWDcHld0WNUEi6
Ky3klIXh6MSdxmilsKP8Z35wugJZS3dCkTm59c3hTO/AO0iMpuUhXf1qarunFjVg
0uat80YpyejDi+l5wGphZxWy8P3laLxiX27Pmd3vG2P+kmWrAgMBAAGjgaYwgaMw
HQYDVR0OBBYEFIgnFwmpthhgi+zruvZHWcVSVKO3MA8GA1UdEwEB/wQFMAMBAf8w
HwYDVR0jBBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wLgYDVR0fBCcwJTAjoCGg
H4YdaHR0cDovL2NybC5hcHBsZS5jb20vcm9vdC5jcmwwDgYDVR0PAQH/BAQDAgGG
MBAGCiqGSIb3Y2QGAgEEAgUAMA0GCSqGSIb3DQEBBQUAA4IBAQBPz+9Zviz1smwv
j+4ThzLoBTWobot9yWkMudkXvHcs1Gfi/ZptOllc34MBvbKuKmFysa/Nw0Uwj6OD
Dc4dR7Txk4qjdJukw5hyhzs+r0ULklS5MruQGFNrCk4QttkdUGwhgAqJTleMa1s8
Pab93vcNIx0LSiaHP7qRkkykGRIZbVf1eliHe2iK5IaMSuviSRSqpd1VAKmuu0sw
ruGgsbwpgOYJd+W+NKIByn/c4grmO7i77LpilfMFY0GCzQ87HUyVpNur+cmV6U/k
TecmmYHpvPm0KdIBembhLoz2IYrF+Hjhga6/05Cdqa3zr/04GpZnMBxRpVzscYqC
tGwPDBUf
-----END CERTIFICATE-----`

const AppleDevCACertG3 = `-----BEGIN CERTIFICATE-----
MIIEUTCCAzmgAwIBAgIQfK9pCiW3Of57m0R6wXjF7jANBgkqhkiG9w0BAQsFADBi
MQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBw
bGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3Qg
Q0EwHhcNMjAwMjE5MTgxMzQ3WhcNMzAwMjIwMDAwMDAwWjB1MUQwQgYDVQQDDDtB
cHBsZSBXb3JsZHdpZGUgRGV2ZWxvcGVyIFJlbGF0aW9ucyBDZXJ0aWZpY2F0aW9u
IEF1dGhvcml0eTELMAkGA1UECwwCRzMxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJ
BgNVBAYTAlVTMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2PWJ/KhZ
C4fHTJEuLVaQ03gdpDDppUjvC0O/LYT7JF1FG+XrWTYSXFRknmxiLbTGl8rMPPbW
BpH85QKmHGq0edVny6zpPwcR4YS8Rx1mjjmi6LRJ7TrS4RBgeo6TjMrA2gzAg9Dj
+ZHWp4zIwXPirkbRYp2SqJBgN31ols2N4Pyb+ni743uvLRfdW/6AWSN1F7gSwe0b
5TTO/iK1nkmw5VW/j4SiPKi6xYaVFuQAyZ8D0MyzOhZ71gVcnetHrg21LYwOaU1A
0EtMOwSejSGxrC5DVDDOwYqGlJhL32oNP/77HK6XF8J4CjDgXx9UO0m3JQAaN4LS
VpelUkl8YDib7wIDAQABo4HvMIHsMBIGA1UdEwEB/wQIMAYBAf8CAQAwHwYDVR0j
BBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wRAYIKwYBBQUHAQEEODA2MDQGCCsG
AQUFBzABhihodHRwOi8vb2NzcC5hcHBsZS5jb20vb2NzcDAzLWFwcGxlcm9vdGNh
MC4GA1UdHwQnMCUwI6AhoB+GHWh0dHA6Ly9jcmwuYXBwbGUuY29tL3Jvb3QuY3Js
MB0GA1UdDgQWBBQJ/sAVkPmvZAqSErkmKGMMl+ynsjAOBgNVHQ8BAf8EBAMCAQYw
EAYKKoZIhvdjZAYCAQQCBQAwDQYJKoZIhvcNAQELBQADggEBAK1lE+j24IF3RAJH
Qr5fpTkg6mKp/cWQyXMT1Z6b0KoPjY3L7QHPbChAW8dVJEH4/M/BtSPp3Ozxb8qA
HXfCxGFJJWevD8o5Ja3T43rMMygNDi6hV0Bz+uZcrgZRKe3jhQxPYdwyFot30ETK
XXIDMUacrptAGvr04NM++i+MZp+XxFRZ79JI9AeZSWBZGcfdlNHAwWx/eCHvDOs7
bJmCS1JgOLU5gm3sUjFTvg+RTElJdI+mUcuER04ddSduvfnSXPN/wmwLCTbiZOTC
NwMUGdXqapSqqdv+9poIZ4vvK7iqF0mDr8/LvOnP6pVxsLRFoszlh6oKw0E6eVza
UDSdlTs=
-----END CERTIFICATE-----`

const AppleRootCACert = `-----BEGIN CERTIFICATE-----
MIIEuzCCA6OgAwIBAgIBAjANBgkqhkiG9w0BAQUFADBiMQswCQYDVQQGEwJVUzET
MBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlv
biBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwHhcNMDYwNDI1MjE0
MDM2WhcNMzUwMjA5MjE0MDM2WjBiMQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBw
bGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkx
FjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDkkakJH5HbHkdQ6wXtXnmELes2oldMVeyLGYne+Uts9QerIjAC6Bg+
+FAJ039BqJj50cpmnCRrEdCju+QbKsMflZ56DKRHi1vUFjczy8QPTc4UadHJGXL1
XQ7Vf1+b8iUDulWPTV0N8WQ1IxVLFVkds5T39pyez1C6wVhQZ48ItCD3y6wsIG9w
tj8BMIy3Q88PnT3zK0koGsj+zrW5DtleHNbLPbU6rfQPDgCSC7EhFi501TwN22IW
q6NxkkdTVcGvL0Gz+PvjcM3mo0xFfh9Ma1CWQYnEdGILEINBhzOKgbEwWOxaBDKM
aLOPHd5lc/9nXmW8Sdh2nzMUZaF3lMktAgMBAAGjggF6MIIBdjAOBgNVHQ8BAf8E
BAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUK9BpR5R2Cf70a40uQKb3
R01/CF4wHwYDVR0jBBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wggERBgNVHSAE
ggEIMIIBBDCCAQAGCSqGSIb3Y2QFATCB8jAqBggrBgEFBQcCARYeaHR0cHM6Ly93
d3cuYXBwbGUuY29tL2FwcGxlY2EvMIHDBggrBgEFBQcCAjCBthqBs1JlbGlhbmNl
IG9uIHRoaXMgY2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFzc3VtZXMgYWNjZXB0
YW5jZSBvZiB0aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJkIHRlcm1zIGFuZCBj
b25kaXRpb25zIG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5IGFuZCBjZXJ0aWZp
Y2F0aW9uIHByYWN0aWNlIHN0YXRlbWVudHMuMA0GCSqGSIb3DQEBBQUAA4IBAQBc
NplMLXi37Yyb3PN3m/J20ncwT8EfhYOFG5k9RzfyqZtAjizUsZAS2L70c5vu0mQP
y3lPNNiiPvl4/2vIB+x9OYOLUyDTOMSxv5pPCmv/K/xZpwUJfBdAVhEedNO3iyM7
R6PVbyTi69G3cN8PReEnyvFteO3ntRcXqNx+IjXKJdXZD9Zr1KIkIxH3oayPc4Fg
xhtbCS+SsvhESPBgOJ4V9T0mZyCKM2r3DYLP3uujL/lTaltkwGMzd/c6ByxW69oP
IQ7aunMZT7XZNn/Bh1XZp5m5MkL72NVxnn6hUrcbvZNCJBIqxw8dtk2cXmPIS4AX
UKqK1drk/NAJBzewdXUh
-----END CERTIFICATE-----`
