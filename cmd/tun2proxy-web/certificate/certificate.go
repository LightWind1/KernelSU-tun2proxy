// Package certificate handles public certificates only. It has no proxy lifecycle dependencies.
package certificate

import (
	"bytes"
	"crypto/md5" // Android subject_hash_old is MD5(subject DER), not a security identifier.
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"time"
)

const MaxSize = 256 * 1024

var idPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

func ValidID(id string) bool { return idPattern.MatchString(id) }

type Certificate struct {
	ID          string    `json:"id"`
	SHA256      string    `json:"sha256"`
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	Serial      string    `json:"serial"`
	NotBefore   time.Time `json:"notBefore"`
	NotAfter    time.Time `json:"notAfter"`
	Algorithm   string    `json:"algorithm"`
	Type        string    `json:"certificateType"`
	SubjectHash string    `json:"subjectHashOld"`
	Parsed      bool      `json:"parsed"`
	IsCA        bool      `json:"isCA"`
	DER         []byte    `json:"-"`
}
type envelope struct {
	TBS       asn1.RawValue
	Algorithm pkix.AlgorithmIdentifier
	Signature asn1.BitString
}
type tbsCert struct {
	Raw       asn1.RawContent
	Version   int `asn1:"optional,explicit,default:0,tag:0"`
	Serial    *big.Int
	Signature pkix.AlgorithmIdentifier
	Issuer    asn1.RawValue
	Validity  struct{ NotBefore, NotAfter time.Time }
	Subject   asn1.RawValue
	PublicKey struct {
		Algorithm pkix.AlgorithmIdentifier
		Key       asn1.BitString
	}
	IssuerID   asn1.BitString   `asn1:"optional,tag:1"`
	SubjectID  asn1.BitString   `asn1:"optional,tag:2"`
	Extensions []pkix.Extension `asn1:"optional,explicit,tag:3"`
}

func Parse(data []byte) (Certificate, error) {
	var c Certificate
	if len(data) == 0 || len(data) > MaxSize {
		return c, errors.New("certificate size invalid")
	}
	if bytes.Contains(bytes.ToUpper(data), []byte("PRIVATE KEY")) {
		return c, errors.New("private keys are forbidden")
	}
	der := data
	if bytes.Contains(data, []byte("-----BEGIN")) {
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 || len(block.Headers) != 0 {
			return c, errors.New("expected exactly one public CERTIFICATE PEM block")
		}
		der = block.Bytes
	}
	var env envelope
	rest, err := asn1.Unmarshal(der, &env)
	if err != nil || len(rest) != 0 || len(env.Signature.Bytes) == 0 {
		return c, errors.New("invalid X.509 DER certificate (HTML is not a certificate)")
	}
	var tbs tbsCert
	rest, err = asn1.Unmarshal(env.TBS.FullBytes, &tbs)
	if err != nil || len(rest) != 0 || tbs.Serial == nil || len(tbs.PublicKey.Key.Bytes) == 0 {
		return c, errors.New("invalid X.509 certificate structure")
	}
	var subject, issuer pkix.RDNSequence
	if _, err = asn1.Unmarshal(tbs.Subject.FullBytes, &subject); err != nil {
		return c, err
	}
	if _, err = asn1.Unmarshal(tbs.Issuer.FullBytes, &issuer); err != nil {
		return c, err
	}
	var sn, in pkix.Name
	sn.FillFromRDNSequence(&subject)
	in.FillFromRDNSequence(&issuer)
	hash := sha256.Sum256(der)
	old := md5.Sum(tbs.Subject.FullBytes)
	c = Certificate{ID: hex.EncodeToString(hash[:]), SHA256: hex.EncodeToString(hash[:]), Subject: sn.String(), Issuer: in.String(), Serial: tbs.Serial.Text(16), NotBefore: tbs.Validity.NotBefore, NotAfter: tbs.Validity.NotAfter, SubjectHash: fmt.Sprintf("%08x", binary.LittleEndian.Uint32(old[:4])), DER: der, Type: "normal", Algorithm: env.Algorithm.Algorithm.String(), Parsed: true}
	if x, e := x509.ParseCertificate(der); e == nil {
		c.Algorithm = x.PublicKeyAlgorithm.String() + " / " + x.SignatureAlgorithm.String()
		c.IsCA = x.IsCA
	} else {
		// Strict ASN.1 metadata decoding for SM2 only, NOT a claim of signature verification.
		var curve asn1.ObjectIdentifier
		_, _ = asn1.Unmarshal(tbs.PublicKey.Algorithm.Parameters.FullBytes, &curve)
		if curve.String() != "1.2.156.10197.1.301" {
			return Certificate{}, fmt.Errorf("unsupported certificate: %w", e)
		}
		c.Type = "gm"
		c.Algorithm = "SM2 / signature OID " + env.Algorithm.Algorithm.String()
		for _, ext := range tbs.Extensions {
			if ext.Id.String() == "2.5.29.19" {
				var bc struct {
					CA      bool `asn1:"optional"`
					PathLen int  `asn1:"optional,default:-1"`
				}
				if _, e = asn1.Unmarshal(ext.Value, &bc); e == nil {
					c.IsCA = bc.CA
				}
			}
		}
	}
	if !c.IsCA {
		return Certificate{}, errors.New("certificate is not a CA")
	}
	return c, nil
}
func (c Certificate) PEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.DER})
}
func AllocateName(c Certificate, existing map[string]string) (string, bool) {
	for name, id := range existing {
		if id == c.ID {
			return name, true
		}
	}
	for i := 0; ; i++ {
		name := fmt.Sprintf("%s.%d", c.SubjectHash, i)
		id, ok := existing[name]
		if !ok {
			return name, false
		}
		if id == c.ID {
			return name, true
		}
	}
}
