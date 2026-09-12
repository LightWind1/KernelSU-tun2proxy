package yakit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDiscoveryFixtures(t *testing.T) {
	cases := []struct {
		name, body             string
		recognized, normal, gm bool
	}{
		{"both", `<title>Yakit MITM</title><a href="/n"><span>证书下载</span></a><a href="/g">国密证书下载</a>`, true, true, true},
		{"missing-normal", `Yakit MITM<a href="/g">国密证书下载</a>`, true, false, true},
		{"missing-gm", `Yakit MITM<a href="/n">证书下载</a>`, true, true, false},
		{"changed-html", `<h1>Yakit MITM</h1><a class='button' href='/new-ca'><b>Certificate download</b></a>`, true, true, false},
		{"javascript", `Yakit MITM<script>fetch('/normal-cert');fetch('/gm-cert')</script>`, true, true, true},
		{"error", `<html>proxy error</html>`, false, false, false},
		{"burp", `<title>Burp Suite</title><a href="/cert">CA certificate</a>`, false, false, false},
		{"private-key", `Yakit MITM<a href="/download-private-key">证书下载</a>`, true, false, false},
		{"external", `Yakit MITM<a href="http://evil/cert">证书下载</a>`, true, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := ParsePage(c.body)
			if d.Recognized != c.recognized || (d.Normal != "") != c.normal || (d.GM != "") != c.gm {
				t.Fatalf("%+v", d)
			}
		})
	}
}
func TestProxyProtocolAndErrors(t *testing.T) {
	for _, code := range []int{200, 404, 407} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.RequestURI != "http://mitm/" || r.Host != "mitm" {
					t.Errorf("not absolute proxy request: %s %s", r.RequestURI, r.Host)
				}
				if r.Header.Get("Proxy-Authorization") == "" {
					t.Error("existing authentication not forwarded")
				}
				w.WriteHeader(code)
				if code == 200 {
					w.Write([]byte("Yakit MITM"))
				}
			}))
			defer srv.Close()
			c, e := New(strings.Replace(srv.URL, "http://", "http://user:secret@", 1))
			if e != nil {
				t.Fatal(e)
			}
			if strings.Contains(c.Proxy, "secret") {
				t.Fatal("secret disclosure")
			}
			d, e := c.Discover(context.Background())
			if d.HTTPStatus != code || (e == nil) != (code == 200) {
				t.Fatalf("%+v %v", d, e)
			}
		})
	}
}
func TestValidation(t *testing.T) {
	for _, raw := range []string{"http://127.0.0.1:0", "http://127.0.0.1:65536", "http://a;b:80", "http://0.0.0.0:80", "socks5://a:80", "http://a:80/path", "http://a:bad"} {
		if _, e := New(raw); e == nil {
			t.Fatal(raw)
		}
	}
	for _, ep := range []string{"http://mitm/private-key", "http://mitm/cert.p12", "http://other/cert", "file:///cert", "http://mitm/../key", "http://mitm/%70rivate"} {
		if safeEndpoint(ep) {
			t.Fatal(ep)
		}
	}
}
