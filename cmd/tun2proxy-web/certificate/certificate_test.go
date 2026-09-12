package certificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T, serial int64) Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "test CA"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	c, e := Parse(der)
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func TestParser(t *testing.T) {
	c := fixture(t, 1)
	for _, b := range [][]byte{c.DER, c.PEM()} {
		p, e := Parse(b)
		if e != nil || p.ID != c.ID {
			t.Fatal(e)
		}
	}
	for _, b := range [][]byte{[]byte("<html>error</html>"), []byte("bad"), append(c.PEM(), []byte("-----BEGIN PRIVATE KEY-----")...)} {
		if _, e := Parse(b); e == nil {
			t.Fatal("accepted invalid")
		}
	}
}
func TestStoreCollisionAndLifecycle(t *testing.T) {
	a, b := fixture(t, 1), fixture(t, 2)
	m := map[string]string{}
	n, dup := AllocateName(a, m)
	if !strings.HasSuffix(n, ".0") || dup {
		t.Fatal(n)
	}
	m[n] = a.ID
	if n, d := AllocateName(a, m); !d || !strings.HasSuffix(n, ".0") {
		t.Fatal(n)
	}
	n, _ = AllocateName(b, m)
	if !strings.HasSuffix(n, ".1") {
		t.Fatal(n)
	}
	s := Store{t.TempDir()}
	v, _ := s.Load()
	s.Put(&v, a, "import")
	s.Put(&v, a, "import")
	if len(v.Entries) != 1 {
		t.Fatal("duplicate")
	}
	e := v.Entries[a.ID]
	e.Managed = true
	v.Entries[a.ID] = e
	s.Save(v)
	if s.Delete(&v, a.ID) == nil {
		t.Fatal("deleted installed CA")
	}
	e.Managed = false
	v.Entries[a.ID] = e
	if err := s.Delete(&v, a.ID); err != nil {
		t.Fatal(err)
	}
	p, _ := s.Path(a.ID)
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal(err)
	}
}
func TestIDs(t *testing.T) {
	s := Store{t.TempDir()}
	for _, id := range []string{"../", "/system/a", "a;id", strings.Repeat("G", 64), "0"} {
		if _, e := s.Path(id); e == nil {
			t.Fatal(id)
		}
	}
}
func TestGMMetadataOnly(t *testing.T) {
	// Synthetic unsupported SM2 curve: metadata decoding must not imply trust.
	c := fixture(t, 3)
	var env envelope
	asn1.Unmarshal(c.DER, &env)
	var tbs tbsCert
	asn1.Unmarshal(env.TBS.FullBytes, &tbs)
	tbs.Raw = nil
	curve, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301})
	tbs.PublicKey.Algorithm.Parameters = asn1.RawValue{FullBytes: curve}
	tbs.Signature.Algorithm = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 501}
	der, e := asn1.Marshal(tbs)
	if e != nil {
		t.Fatal(e)
	}
	env.TBS = asn1.RawValue{FullBytes: der}
	env.Algorithm = tbs.Signature
	raw, e := asn1.Marshal(env)
	if e != nil {
		t.Fatal(e)
	}
	parsed, e := Parse(raw)
	if e != nil || parsed.Type != "gm" || !parsed.IsCA {
		t.Fatalf("%+v %v", parsed, e)
	}
}
