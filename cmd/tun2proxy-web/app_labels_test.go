package main

import "testing"

func TestParseAppLabels(t *testing.T) {
	got := parseAppLabels([]byte("com.android.browser\t浏览器\ncom.example.chat\tChat App\r\ninvalid\n\tempty\ncom.empty\t  \n"))
	if got["com.android.browser"] != "浏览器" || got["com.example.chat"] != "Chat App" {
		t.Fatalf("app labels parsed incorrectly: %#v", got)
	}
	if _, ok := got["com.empty"]; ok {
		t.Fatal("empty label must not be indexed")
	}
}
