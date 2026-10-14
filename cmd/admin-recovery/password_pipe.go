package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"syscall"
	"time"
	"unicode/utf8"
)

func readPasswordPipe() ([]byte, error) {
	// Reject missing/terminal/runtime descriptors before changing flags or taking ownership.
	info, err := os.Stat("/dev/fd/3")
	if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		return nil, errors.New("inherited password pipe unavailable")
	}
	// NewFile only registers inherited Unix descriptors with the poller in non-blocking mode.
	if err := syscall.SetNonblock(3, true); err != nil {
		return nil, errors.New("password pipe unavailable")
	}
	pipe := os.NewFile(3, "recovery-password-pipe")
	if pipe == nil {
		return nil, errors.New("password pipe unavailable")
	}
	password, readErr := readPassword(pipe)
	closeErr := pipe.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		clear(password)
		return nil, errors.New("password pipe close failed")
	}
	return password, nil
}

func readPassword(pipe *os.File) ([]byte, error) {
	if err := pipe.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return nil, errors.New("password pipe must support deadlines")
	}
	raw, err := io.ReadAll(io.LimitReader(pipe, 131))
	if err != nil {
		clear(raw)
		return nil, errors.New("password pipe read failed")
	}
	password := bytes.TrimSuffix(bytes.TrimSuffix(raw, []byte("\n")), []byte("\r"))
	if len(password) == 0 || len(password) > 128 || !utf8.Valid(password) || bytes.ContainsAny(password, "\r\n\x00") {
		clear(raw)
		return nil, errors.New("password pipe must contain one bounded line")
	}
	return password, nil
}
