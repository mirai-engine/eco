//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"strconv"
	"syscall"
	"time"
	"unsafe"
)

func prepareCmd(cmd *exec.Cmd) {}

// killTree terminates the process and all its descendants (a plain Kill would leave children running).
func killTree(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = exec.Command("taskkill", "/T", "/F", "/PID", strconv.Itoa(cmd.Process.Pid)).Run()
	_ = cmd.Process.Kill()
}

var (
	user32            = syscall.NewLazyDLL("user32.dll")
	messageBoxTimeout = user32.NewProc("MessageBoxTimeoutW")
	findWindow        = user32.NewProc("FindWindowW")
	postMessage       = user32.NewProc("PostMessageW")
)

const dialogTitle = "eco pairing request"

// closeApprovalDialog removes a dialog that is no longer needed (answered in the terminal).
func closeApprovalDialog() {
	if findWindow.Find() != nil {
		return
	}
	c, _ := syscall.UTF16PtrFromString(dialogTitle)
	if h, _, _ := findWindow.Call(0, uintptr(unsafe.Pointer(c))); h != 0 {
		const wmClose = 0x10
		postMessage.Call(h, wmClose, 0, 0)
	}
}

// approvalDialog shows a Yes/No dialog on the desktop, so a pairing request is noticed even when the
// server console is hidden. It closes itself after timeout. The channel gets the answer, or nothing.
func approvalDialog(r pairRequest, timeout time.Duration) <-chan bool {
	ch := make(chan bool, 1)
	if messageBoxTimeout.Find() != nil {
		return ch
	}
	text := fmt.Sprintf("%s (%s) wants to pair with this eco server.\n\nCode: %s\n\nApprove only if the other machine shows exactly the same code.",
		r.Name, r.Remote, r.Code)
	go func() {
		t, _ := syscall.UTF16PtrFromString(text)
		c, _ := syscall.UTF16PtrFromString(dialogTitle)
		const (
			mbYesNo        = 0x4
			mbIconQuestion = 0x20
			mbDefButton2   = 0x100 // "No" is the default
			mbSystemModal  = 0x1000
			mbSetFG        = 0x10000
			mbTopmost      = 0x40000
			idYes          = 6
			idNo           = 7
		)
		ret, _, _ := messageBoxTimeout.Call(0, uintptr(unsafe.Pointer(t)), uintptr(unsafe.Pointer(c)),
			mbYesNo|mbIconQuestion|mbDefButton2|mbSystemModal|mbSetFG|mbTopmost, 0, uintptr(timeout/time.Millisecond))
		switch ret {
		case idYes:
			ch <- true
		case idNo:
			ch <- false
		}
	}()
	return ch
}
