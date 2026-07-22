package docker

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"tguard-installer/pkg/system"
)

// defaultTimeout untuk operasi Docker yang seharusnya tidak lama
const (
	daemonCheckTimeout   = 60 * time.Second  // wait up to 1 min for daemon
	composeUpTimeout     = 45 * time.Minute  // image pull on slow networks can take time
	installDockerTimeout = 15 * time.Minute  // installation + download
)

// IsInstalled checks if docker is installed
func IsInstalled() bool {
	return system.CommandExists("docker")
}

// Install automatically downloads and installs Docker via get.docker.com
func Install() error {
	// Ensure curl is installed
	if !system.CommandExists("curl") {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		_ = exec.CommandContext(ctx, "apt-get", "update").Run()
		if err := exec.CommandContext(ctx, "apt-get", "install", "-y", "curl").Run(); err != nil {
			return fmt.Errorf("failed to install curl: %w", err)
		}
	}

	scriptPath := "/tmp/get-docker.sh"

	// Pastikan file temp terhapus walau gagal di tengah
	defer os.Remove(scriptPath)

	// Download Docker installation script dengan timeout
	ctx, cancel := context.WithTimeout(context.Background(), installDockerTimeout)
	defer cancel()

	dlCmd := exec.CommandContext(ctx, "curl", "-fsSL", "https://get.docker.com", "-o", scriptPath)
	if out, err := dlCmd.CombinedOutput(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("docker install script download timed out after %v", installDockerTimeout)
		}
		return fmt.Errorf("failed to download docker install script: %w\n%s", err, string(out))
	}

	// Jalankan script instalasi
	installCtx, installCancel := context.WithTimeout(context.Background(), installDockerTimeout)
	defer installCancel()

	installCmd := exec.CommandContext(installCtx, "sh", scriptPath)
	if out, err := installCmd.CombinedOutput(); err != nil {
		if installCtx.Err() != nil {
			return fmt.Errorf("docker installation timed out after %v", installDockerTimeout)
		}
		return fmt.Errorf("failed to run docker install script: %w\n%s", err, string(out))
	}

	return nil
}

// EnsureDaemon checks if the daemon is running, attempts to start it if not
func EnsureDaemon() error {
	if !IsInstalled() {
		fmt.Println("Docker is not installed. Attempting to install Docker automatically...")
		if err := Install(); err != nil {
			return fmt.Errorf("failed to install docker automatically: %w", err)
		}
	}

	// Cek daemon dengan timeout
	checkCtx, checkCancel := context.WithTimeout(context.Background(), daemonCheckTimeout)
	defer checkCancel()

	if err := exec.CommandContext(checkCtx, "docker", "info").Run(); err == nil {
		return nil
	}

	// Coba restart daemon
	if system.CommandExists("systemctl") {
		restartCtx, restartCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer restartCancel()

		_ = exec.CommandContext(restartCtx, "systemctl", "daemon-reload").Run()
		_ = exec.CommandContext(restartCtx, "systemctl", "start", "containerd").Run()
		_ = exec.CommandContext(restartCtx, "systemctl", "restart", "docker").Run()
	}

	// Tunggu sebentar lalu cek lagi
	time.Sleep(3 * time.Second)

	verifyCtx, verifyCancel := context.WithTimeout(context.Background(), daemonCheckTimeout)
	defer verifyCancel()

	if err := exec.CommandContext(verifyCtx, "docker", "info").Run(); err != nil {
		if verifyCtx.Err() != nil {
			return fmt.Errorf("docker daemon check timed out — daemon may be hung")
		}
		return fmt.Errorf("docker daemon is unresponsive after restart attempt")
	}
	return nil
}

// HasCompose checks if docker compose plugin or docker-compose is available
func HasCompose() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "docker", "compose", "version").Run(); err == nil {
		return true
	}
	return system.CommandExists("docker-compose")
}

// GetDockerRoot returns the current docker data root
func GetDockerRoot() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "info", "-f", "{{.DockerRootDir}}")
	out, err := cmd.Output()
	if err != nil {
		return "/var/lib/docker", fmt.Errorf("failed to get docker root: %w", err)
	}
	root := strings.TrimSpace(string(out))
	if root == "" {
		return "/var/lib/docker", nil
	}
	return root, nil
}

// ComposeUp runs docker compose up -d in the specified directory with timeout
func ComposeUp(dir string) error {
	// Validasi direktori ada dulu
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return fmt.Errorf("compose directory not found: %s", dir)
	}

	ctx, cancel := context.WithTimeout(context.Background(), composeUpTimeout)
	defer cancel()

	var cmd *exec.Cmd

	// Prioritaskan docker compose plugin (V2)
	checkCtx, checkCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer checkCancel()

	if err := exec.CommandContext(checkCtx, "docker", "compose", "version").Run(); err == nil {
		cmd = exec.CommandContext(ctx, "docker", "compose", "up", "-d", "--remove-orphans")
	} else {
		// Fallback ke docker-compose (V1)
		if !system.CommandExists("docker-compose") {
			return fmt.Errorf("neither 'docker compose' plugin nor 'docker-compose' binary found")
		}
		cmd = exec.CommandContext(ctx, "docker-compose", "up", "-d", "--remove-orphans")
	}

	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("docker compose up timed out after %v in %s (image pull may have stalled)", composeUpTimeout, dir)
		}
		return fmt.Errorf("docker compose up failed in %s:\n%s", dir, string(out))
	}
	return nil
}
