//go:build windows

package main

import (
	"syscall"
	"unicode/utf16"
	"unsafe"
)

const (
	mbOKCANCEL = 0x00000001
	mbICONWARN = 0x00000030
	idOK       = 1
)

func messageBoxConfirmWindows(message string) bool {
	user32 := syscall.NewLazyDLL("user32.dll")
	proc := user32.NewProc("MessageBoxW")
	title := "OpenClaw 保护确认"
	ret, _, _ := proc.Call(0,
		uintptr(unsafe.Pointer(syscallStringToUTF16Ptr(message))),
		uintptr(unsafe.Pointer(syscallStringToUTF16Ptr(title))),
		uintptr(mbOKCANCEL|mbICONWARN))
	return ret == idOK
}

func syscallStringToUTF16Ptr(s string) *uint16 {
	u := utf16.Encode([]rune(s + "\x00"))
	return &u[0]
}
