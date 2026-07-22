package system

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// EnsureUbuntuHost checks if the OS is Ubuntu/Debian compatible
func EnsureUbuntuHost() error {
	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return fmt.Errorf("must be run on a Linux host with /etc/os-release: %v", err)
	}

	content := strings.ToLower(string(b))
	if !strings.Contains(content, "ubuntu") && !strings.Contains(content, "debian") {
		return fmt.Errorf("incompatible host. Only Ubuntu/Debian are supported")
	}
	return nil
}

// EnsureSudoReady checks if sudo is available and user has privileges
func EnsureSudoReady() error {
	if os.Getuid() == 0 {
		return nil // Already root
	}

	_, err := exec.LookPath("sudo")
	if err != nil {
		return fmt.Errorf("sudo is not installed. Run as root or install sudo")
	}

	cmd := exec.Command("sudo", "-v")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("user does not have sudo privileges")
	}
	return nil
}

// CommandExists checks if an executable exists in PATH
func CommandExists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

// RunSudoCmd runs a command with sudo, or directly if already root
func RunSudoCmd(name string, arg ...string) error {
	if os.Getuid() == 0 {
		cmd := exec.Command(name, arg...)
		return cmd.Run()
	}
	
	args := append([]string{name}, arg...)
	cmd := exec.Command("sudo", args...)
	return cmd.Run()
}
