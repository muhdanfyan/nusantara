package state

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const stateDir = "/var/lib/tguard_state"

// IsStepDone memeriksa apakah sebuah step sudah pernah dijalankan sebelumnya (idempotency)
func IsStepDone(stepName string) bool {
	_, err := os.Stat(filepath.Join(stateDir, stepName+".done"))
	return err == nil
}

// MarkStepDone mencatat bahwa sebuah step sudah selesai
func MarkStepDone(stepName string) error {
	if err := os.MkdirAll(stateDir, 0755); err != nil {
		// State dir gagal dibuat (mungkin non-root), tidak fatal — skip saja
		return nil
	}
	f, err := os.Create(filepath.Join(stateDir, stepName+".done"))
	if err != nil {
		return nil // tidak fatal
	}
	defer f.Close()
	_, _ = fmt.Fprintf(f, "completed at: %s\n", time.Now().Format(time.RFC3339))
	return nil
}

// ResetAllSteps menghapus semua state (untuk uninstall / force reinstall)
func ResetAllSteps() error {
	return os.RemoveAll(stateDir)
}
