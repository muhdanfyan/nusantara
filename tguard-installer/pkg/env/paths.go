package env

import (
	"fmt"
	"os"
	"path/filepath"
)

type InstallerPaths struct {
	RootDir string
	DataDir string
	LogDir  string
}

// InitPaths resolves absolute paths reliably regardless of where the binary is executed from.
func InitPaths() (*InstallerPaths, error) {
	// 1. Dapatkan lokasi absolut dari binari yang sedang berjalan
	exePath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("failed to get executable path: %v", err)
	}
	
	// Selesaikan symlink jika ada
	realExePath, err := filepath.EvalSymlinks(exePath)
	if err == nil {
		exePath = realExePath
	}
	
	scriptDir := filepath.Dir(exePath)

	// 2. Tentukan ROOT_DIR (Root dari proyek t-guard)
	// Jika ada env TGUARD_ROOT_DIR, gunakan itu.
	rootDir := os.Getenv("TGUARD_ROOT_DIR")
	if rootDir == "" {
		// Logika pencarian cerdas: Binari mungkin ada di "t-guard/tguard-installer/" 
		// atau dipindahkan langsung ke "t-guard/".
		// Kita cek keberadaan folder "wazuh-docker" sebagai indikator root proyek.
		if _, err := os.Stat(filepath.Join(scriptDir, "wazuh-docker")); err == nil {
			rootDir = scriptDir
		} else if _, err := os.Stat(filepath.Join(filepath.Dir(scriptDir), "wazuh-docker")); err == nil {
			rootDir = filepath.Dir(scriptDir) // Naik satu level
		} else {
			// Fallback aman
			rootDir = scriptDir 
		}
	}
	
	// Pastikan rootDir adalah absolute path
	if !filepath.IsAbs(rootDir) {
		rootDir = filepath.Join(scriptDir, rootDir)
	}
	rootDir = filepath.Clean(rootDir)

	// 3. Tentukan DATA_DIR
	dataDir := os.Getenv("TGUARD_DATA_DIR")
	if dataDir == "" {
		dataDir = rootDir
	}
	if !filepath.IsAbs(dataDir) {
		dataDir = filepath.Join(rootDir, dataDir)
	}
	dataDir = filepath.Clean(dataDir)
	
	// Buat DATA_DIR jika belum ada
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create DATA_DIR (%s): %v", dataDir, err)
	}

	// 4. Tentukan LOG_DIR
	logDir := os.Getenv("TGUARD_LOG_DIR")
	if logDir == "" {
		logDir = filepath.Join(dataDir, "logs")
	}
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create LOG_DIR (%s): %v", logDir, err)
	}

	return &InstallerPaths{
		RootDir: rootDir,
		DataDir: dataDir,
		LogDir:  logDir,
	}, nil
}
