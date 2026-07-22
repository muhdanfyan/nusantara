package orchestration

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// InjectN8nWorkflow membaca file template n8n JSON dari disk lalu menginjeksinya langsung ke engine
// n8n yang sedang berjalan menggunakan REST API. Ini jauh lebih tangguh daripada eksekusi docker CLI.
func InjectN8nWorkflow(workflowPath string, n8nAPIUrl string, apiKey string) error {
	// 1. Baca file workflow
	payload, err := os.ReadFile(workflowPath)
	if err != nil {
		return fmt.Errorf("gagal membaca file workflow dari path %s: %v", workflowPath, err)
	}

	client := http.Client{Timeout: 10 * time.Second}

	// 2. Tunggu sampai n8n benar-benar siap (Polling API Healthcheck)
	ready := false
	for i := 0; i < 30; i++ { // Coba selama 90 detik maksimal
		resp, err := client.Get(fmt.Sprintf("%s/healthz", n8nAPIUrl))
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				ready = true
				break
			}
		}
		time.Sleep(3 * time.Second)
	}

	if !ready {
		return fmt.Errorf("n8n di %s tidak merespons (Timeout)", n8nAPIUrl)
	}

	// 3. Tembak payload JSON langsung ke Endpoint Workflow n8n
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/api/v1/workflows", n8nAPIUrl), bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("gagal membuat http request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("X-N8N-API-KEY", apiKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("koneksi ke n8n API terputus saat injeksi: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		errBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("n8n menolak injeksi workflow (Kode %d): %s", resp.StatusCode, string(errBody))
	}

	return nil
}
