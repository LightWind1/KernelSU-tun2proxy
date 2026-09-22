package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"tun2proxy-web/certificate"
)

func transactionFixture(t *testing.T) certificate.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "transaction test"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	c, e := certificate.Parse(der)
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func TestYakitUpdateTransaction(t *testing.T) {
	previousStore, previousApply, previousConfig, previousLog := certStore, certificateApply, configFile, logDir
	defer func() {
		certStore = previousStore
		certificateApply = previousApply
		configFile = previousConfig
		logDir = previousLog
	}()
	certStore = certificate.Store{Dir: t.TempDir()}
	configFile = certStore.Dir + "/proxy.json"
	logDir = t.TempDir()
	oldCA, newCA := transactionFixture(t), transactionFixture(t)
	v, _ := certStore.Load()
	entry, e := certStore.Put(&v, oldCA, "yakit-normal")
	if e != nil {
		t.Fatal(e)
	}
	entry.Managed = true
	v.Entries[entry.ID] = entry
	v.Yakit["normal"] = certificate.Remote{LocalID: oldCA.ID, RemoteID: oldCA.ID}
	certStore.Save(v)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Write([]byte("Yakit MITM"))
			return
		}
		if r.URL.Path == "/download-mitm-crt" {
			w.Write(newCA.PEM())
			return
		}
		http.NotFound(w, r)
	}))
	defer proxy.Close()
	saveConfig(Config{ProxyURL: proxy.URL})
	slot := proxy.URL + "|normal"
	call := func(action string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		yakitAPI(w, httptest.NewRequest("POST", "/api/yakit", strings.NewReader("{\"action\":\""+action+"\",\"kind\":\"normal\"}")))
		return w
	}
	call("check")
	v, _ = certStore.Load()
	if v.Yakit[slot].LocalID != oldCA.ID || v.Yakit[slot].RemoteID != newCA.ID {
		t.Fatal("check replaced local CA")
	}
	certificateApply = func(certificate.Inventory) error { return errors.New("verification failed") }
	call("sync")
	v, _ = certStore.Load()
	if v.Yakit[slot].LocalID != oldCA.ID || !v.Entries[oldCA.ID].Managed {
		t.Fatal("failed update lost old CA")
	}
	if _, ok := v.Entries[newCA.ID]; ok {
		t.Fatal("failed transaction committed new inventory")
	}
	certificateApply = func(certificate.Inventory) error { return nil }
	call("sync")
	v, _ = certStore.Load()
	if v.Yakit[slot].LocalID != newCA.ID || !v.Entries[newCA.ID].Managed || v.Entries[oldCA.ID].Managed {
		t.Fatal("successful update did not switch")
	}
}
func TestInstallRemoveRollback(t *testing.T) {
	originalStore, originalApply, originalLog := certStore, certificateApply, logDir
	defer func() { certStore = originalStore; certificateApply = originalApply; logDir = originalLog }()
	certStore = certificate.Store{Dir: t.TempDir()}
	logDir = t.TempDir()
	c := transactionFixture(t)
	v, _ := certStore.Load()
	if _, e := certStore.Put(&v, c, "import"); e != nil {
		t.Fatal(e)
	}
	if e := certStore.Save(v); e != nil {
		t.Fatal(e)
	}
	call := func(action string) *httptest.ResponseRecorder {
		b, _ := json.Marshal(CertAction{Action: action, ID: c.ID})
		w := httptest.NewRecorder()
		certAction(w, httptest.NewRequest("POST", "/api/certificates/action", strings.NewReader(string(b))))
		return w
	}
	certificateApply = func(v certificate.Inventory) error { return errors.New("simulated mount failure") }
	if w := call("install"); w.Code != 400 {
		t.Fatal(w.Body.String())
	}
	v, _ = certStore.Load()
	if v.Entries[c.ID].Managed {
		t.Fatal("failed install changed inventory")
	}
	certificateApply = func(v certificate.Inventory) error { return nil }
	if w := call("install"); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	v, _ = certStore.Load()
	if !v.Entries[c.ID].Managed {
		t.Fatal("install not committed")
	}
	certificateApply = func(v certificate.Inventory) error { return errors.New("simulated remove failure") }
	if w := call("remove"); w.Code != 400 {
		t.Fatal(w.Body.String())
	}
	v, _ = certStore.Load()
	if !v.Entries[c.ID].Managed {
		t.Fatal("failed remove lost old CA")
	}
	certificateApply = func(v certificate.Inventory) error { return nil }
	if w := call("remove"); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	v, _ = certStore.Load()
	if v.Entries[c.ID].Managed {
		t.Fatal("remove not committed")
	}
	if _, e := certStore.Read(c.ID); e != nil {
		t.Fatal("remove deleted cache", e)
	}
}
