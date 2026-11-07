//go:build windows

package main

import (
	"os/exec"
	"strconv"
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
