// Package yakit requests public CA endpoints through the existing explicit HTTP proxy.
package yakit

import (
	"context"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"tun2proxy-web/certificate"
)

type Discovery struct {
	Proxy      string `json:"proxy"`
	Connected  bool   `json:"connected"`
	Recognized bool   `json:"recognized"`
	HTTPStatus int    `json:"httpStatus"`
	Normal     string `json:"normalEndpoint"`
	GM         string `json:"gmEndpoint"`
	Message    string `json:"message"`
}
type Client struct {
	HTTP  *http.Client
	Proxy string
}

func New(raw string) (*Client, error) {
	u, e := url.Parse(raw)
	if e != nil {
		return nil, errors.New("invalid upstream proxy URL")
	}
	if u.Scheme != "http" {
		return nil, errors.New("Yakit discovery requires the saved HTTP CONNECT upstream")
	}
	p, e := strconv.Atoi(u.Port())
	if e != nil || p < 1 || p > 65535 {
		return nil, errors.New("invalid upstream proxy port")
	}
	h := u.Hostname()
	if h == "" || strings.ContainsAny(h, " /\\;\r\n\t") || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("invalid upstream proxy host")
	}
	if net.ParseIP(h) == nil && !regexp.MustCompile(`^[a-zA-Z0-9.-]+$`).MatchString(h) {
		return nil, errors.New("invalid upstream proxy host")
	}
	if ip := net.ParseIP(h); ip != nil && ip.IsUnspecified() {
		return nil, errors.New("unspecified proxy address")
	}
	tr := &http.Transport{Proxy: http.ProxyURL(u), DialContext: (&net.Dialer{Timeout: 6 * time.Second}).DialContext, ResponseHeaderTimeout: 8 * time.Second, DisableKeepAlives: true}
	safe := *u
	safe.User = nil
	return &Client{HTTP: &http.Client{Transport: tr, Timeout: 12 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) > 3 || !safeEndpoint(r.URL.String()) {
			return errors.New("unsafe redirect")
		}
		return nil
	}}, Proxy: safe.String()}, nil
}
func safeEndpoint(raw string) bool {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "http" || u.Host != "mitm" || u.User != nil || u.Fragment != "" {
		return false
	}
	lower := strings.ToLower(u.Path + "?" + u.RawQuery)
	for _, bad := range []string{"private", "key", "pkcs12", ".p12", ".pfx", "..", "\\"} {
		if strings.Contains(lower, bad) {
			return false
		}
	}
	return true
}
func normalize(s string) string {
	s = html.UnescapeString(s)
	s = strings.ReplaceAll(s, `\/`, "/")
	u, e := url.Parse(s)
	if e != nil {
		return ""
	}
	base, _ := url.Parse("http://mitm/")
	v := base.ResolveReference(u).String()
	if !safeEndpoint(v) {
		return ""
	}
	return v
}

var anchor = regexp.MustCompile(`(?is)<a\b[^>]*href\s*=\s*["']([^"']+)["'][^>]*>(.*?)</a>`)
var stripTags = regexp.MustCompile(`(?s)<[^>]*>`)
var jsURL = regexp.MustCompile(`(?i)(?:fetch\s*\(\s*|(?:href|location|url)\s*[:=]\s*)["']([^"']+)["']`)

func ParsePage(body string) Discovery {
	d := Discovery{}
	low := strings.ToLower(body)
	d.Recognized = strings.Contains(low, "yakit") && (strings.Contains(low, "mitm") || strings.Contains(low, "yaklang"))
	if !d.Recognized {
		d.Message = "当前代理可以连接，但未识别为 Yakit MITM。"
		return d
	}
	for _, m := range anchor.FindAllStringSubmatch(body, -1) {
		label := strings.ToLower(html.UnescapeString(stripTags.ReplaceAllString(m[2], "")))
		ep := normalize(m[1])
		if ep == "" {
			continue
		}
		if strings.Contains(label, "国密") || strings.Contains(label, "gm cert") {
			d.GM = ep
		} else if strings.Contains(label, "证书") || strings.Contains(label, "certificate") {
			d.Normal = ep
		}
	}
	// Only discover literal URLs; never evaluate the remote page's JavaScript.
	for _, m := range jsURL.FindAllStringSubmatch(body, -1) {
		ep := normalize(m[1])
		low := strings.ToLower(ep)
		if !strings.Contains(low, "crt") && !strings.Contains(low, "cert") {
			continue
		}
		if strings.Contains(low, "gm") {
			if d.GM == "" {
				d.GM = ep
			}
		} else if d.Normal == "" {
			d.Normal = ep
		}
	}
	d.Message = "Yakit MITM 可访问"
	return d
}
func (c *Client) get(ctx context.Context, ep string, limit int64) ([]byte, int, error) {
	if !safeEndpoint(ep) {
		return nil, 0, errors.New("unsafe endpoint")
	}
	req, e := http.NewRequestWithContext(ctx, "GET", ep, nil)
	if e != nil {
		return nil, 0, e
	}
	resp, e := c.HTTP.Do(req)
	if e != nil {
		return nil, 0, errors.New("Yakit proxy request failed (connection/timeout)")
	}
	defer resp.Body.Close()
	if resp.StatusCode == 407 {
		return nil, 407, errors.New("upstream proxy authentication required")
	}
	if resp.StatusCode != 200 {
		return nil, resp.StatusCode, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, e := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if e != nil {
		return nil, resp.StatusCode, errors.New("incomplete proxy response")
	}
	if int64(len(b)) > limit {
		return nil, resp.StatusCode, errors.New("proxy response too large")
	}
	return b, resp.StatusCode, nil
}
func (c *Client) Discover(ctx context.Context) (Discovery, error) {
	b, code, e := c.get(ctx, "http://mitm/", 512*1024)
	d := Discovery{Proxy: c.Proxy, Connected: code != 0, HTTPStatus: code}
	if e != nil {
		d.Message = e.Error()
		return d, e
	}
	p := ParsePage(string(b))
	p.Proxy = c.Proxy
	p.Connected = true
	p.HTTPStatus = code
	return p, nil
}
func (c *Client) Download(ctx context.Context, kind string, d Discovery) (certificate.Certificate, string, error) {
	if !d.Recognized {
		return certificate.Certificate{}, "", errors.New("upstream not identified as Yakit")
	}
	if kind != "normal" && kind != "gm" {
		return certificate.Certificate{}, "", errors.New("unknown CA type")
	}
	// Verified in actual Yakit HTML on 2026-09-12. Validate responses, then fallback to discovery.
	known := "http://mitm/download-mitm-crt"
	found := d.Normal
	if kind == "gm" {
		known = "http://mitm/download-mitm-gm-crt"
		found = d.GM
	}
	candidates := []string{known}
	if found != "" && found != known {
		candidates = append(candidates, found)
	}
	for _, ep := range candidates {
		b, _, e := c.get(ctx, ep, certificate.MaxSize)
		if e != nil {
			continue
		}
		cert, e := certificate.Parse(b)
		if e != nil || cert.Type != kind {
			continue
		}
		return cert, ep, nil
	}
	return certificate.Certificate{}, "", fmt.Errorf("%s CA endpoint missing or returned invalid/wrong-type public certificate", kind)
}
