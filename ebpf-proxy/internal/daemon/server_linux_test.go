//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateRuntimeLock(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	f, e := secureRuntime(dir)
	if e != nil {
		t.Fatal(e)
	}
	if f2, e := secureRuntime(dir); e == nil {
		f2.Close()
		t.Fatal("duplicate daemon lock allowed")
	}
	f.Close()
	f, e = secureRuntime(dir)
	if e != nil {
		t.Fatal(e)
	}
	f.Close()
	os.Chmod(dir, 0777)
	if f, e := secureRuntime(dir); e == nil {
		f.Close()
		t.Fatal("public runtime accepted")
	}
	os.Chmod(dir, 0700)
	link := filepath.Join(t.TempDir(), "link")
	os.Symlink(dir, link)
	if f, e := secureRuntime(link); e == nil {
		f.Close()
		t.Fatal("symlink runtime accepted")
	}
}
