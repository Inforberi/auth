package main

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func TestPasswordPipe(t *testing.T) {
	for _, value := range []string{"Syntheticpassword1\n", "Syntheticpassword1\r\n", "", strings.Repeat("x", 129), "line\nline", "secret\x00extra", "Validpass1\xff"} {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(w, value); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		password, err := readPassword(r)
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
		valid := strings.HasPrefix(value, "Syntheticpassword1")
		if valid != (err == nil) {
			t.Fatal("pipe format", err)
		}
		if valid && string(password) != "Syntheticpassword1" {
			t.Fatal("line terminator handling")
		}
		clear(password)
	}
	file, err := os.CreateTemp(t.TempDir(), "not-pipe")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	if _, err := readPassword(file); err == nil {
		t.Fatal("regular password file accepted")
	}
}

func TestInheritedPasswordPipe(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("operator pipe command targets Unix")
	}
	if os.Getenv("AUTH_TEST_PASSWORD_PIPE") == "1" {
		password, err := readPasswordPipe()
		if err != nil {
			t.Fatal(err)
		}
		defer clear(password)
		if !bytes.Equal(password, []byte("Syntheticpassword1")) {
			t.Fatal("inherited pipe corrupted")
		}
		return
	}
	if os.Getenv("AUTH_TEST_PASSWORD_PIPE") == "missing" {
		if _, err := readPasswordPipe(); err == nil {
			t.Fatal("missing descriptor accepted")
		}
		return
	}
	program, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	if _, err := io.WriteString(w, "Syntheticpassword1\n"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	child := exec.Command(program, "-test.run=^TestInheritedPasswordPipe$")
	child.Env = []string{"AUTH_TEST_PASSWORD_PIPE=1"}
	child.ExtraFiles = []*os.File{r}
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("inherited descriptor: %v: %s", err, output)
	}
	missing := exec.Command(program, "-test.run=^TestInheritedPasswordPipe$")
	missing.Env = []string{"AUTH_TEST_PASSWORD_PIPE=missing"}
	if output, err := missing.CombinedOutput(); err != nil {
		t.Fatalf("missing descriptor: %v: %s", err, output)
	}
}
