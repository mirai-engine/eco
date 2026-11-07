//go:build !windows

package main

import (
	"os/exec"
	"syscall"
	"time"
)

// approvalDialog: no desktop dialog on this platform; approve in the terminal.
func approvalDialog(pairRequest, time.Duration) <-chan bool { return nil }

func closeApprovalDialog() {}

// prepareCmd puts the child in its own process group so the whole tree can be killed.
func prepareCmd(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }

func killTree(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	_ = cmd.Process.Kill()
}
