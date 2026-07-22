package orchestration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"tguard-installer/pkg/docker"
	"tguard-installer/pkg/env"
	"tguard-installer/pkg/hardware"
	"tguard-installer/pkg/network"
	"tguard-installer/pkg/state"
	"tguard-installer/pkg/system"
)

// Warna reusable
var (
	cyan  = lipgloss.NewStyle().Foreground(lipgloss.Color("#00e5ff"))
	green = lipgloss.NewStyle().Foreground(lipgloss.Color("#10b981"))
	red   = lipgloss.NewStyle().Foreground(lipgloss.Color("#ef4444"))
	amber = lipgloss.NewStyle().Foreground(lipgloss.Color("#fbbf24"))
	muted = lipgloss.NewStyle().Foreground(lipgloss.Color("#6b7280"))
	bold  = lipgloss.NewStyle().Bold(true)
)

type Config struct {
	NetworkType   string
	SOAREngine    string
	AdvancedMode  bool
	UseVirusTotal bool
	VTAPIKey      string
}

// runStep menjalankan satu step dengan spinner dan log hasilnya
// Jika step sudah pernah berhasil sebelumnya (idempoten), step dilewati
func buildDeploymentSteps(
	cfg Config,
	hw **hardware.ServerHardware,
	hostIP *string,
	paths **env.InstallerPaths,
	wazuhDir *string,
) []*Step {
	steps := []*Step{
		{
			Key:   "preflight",
			Title: "Pre-flight OS & Permissions Check",
			Action: func() (bool, string, error) {
				if state.IsStepDone("preflight") {
					return true, "", nil
				}
				if err := system.EnsureUbuntuHost(); err != nil {
					return false, "", fmt.Errorf("OS check failed: %v", err)
				}
				if err := system.EnsureSudoReady(); err != nil {
					return false, "", fmt.Errorf("sudo check failed: %v", err)
				}
				return false, "", nil
			},
		},
		{
			Key:   "hardware",
			Title: "Hardware Analysis & Smart Mode",
			Action: func() (bool, string, error) {
				isDone := state.IsStepDone("hardware")
				var err error
				*hw, err = hardware.Analyze()
				if err != nil {
					return isDone, "", nil
				}
				os.Setenv("TGUARD_SERVER_TIER", (*hw).Tier)
				os.Setenv("TGUARD_CPU_CORES", fmt.Sprintf("%d", (*hw).CPUCores))

				if isDone {
					return true, "", nil
				}

				var log string
				if (*hw).Tier == "Entry-Level" {
					log = fmt.Sprintf("⚠ Hardware Warning: Entry-Level tier detected!\nCPU: %d cores | RAM: %.1f GB | Disk Free: %.1f GB\nPerformance may be degraded. Consider upgrading to 4+ cores / 8GB RAM.", (*hw).CPUCores, (*hw).TotalRAMGB, (*hw).FreeStorageGB)
				} else {
					log = fmt.Sprintf("ℹ CPU: %d cores | RAM: %.1f GB | Disk Free: %.1f GB | Tier: %s", (*hw).CPUCores, (*hw).TotalRAMGB, (*hw).FreeStorageGB, (*hw).Tier)
				}

				if (*hw).FreeStorageGB < 10.0 {
					return false, log, fmt.Errorf("not enough disk space: %.1f GB free, minimum 10 GB required", (*hw).FreeStorageGB)
				}
				return false, log, nil
			},
		},
		{
			Key:   "network",
			Title: "Network Configuration (IP Detection)",
			Action: func() (bool, string, error) {
				isDone := state.IsStepDone("network")
				if cfg.NetworkType == "Private Network" {
					privateIP, err := network.DetectPrivateIP()
					if err != nil {
						if isDone {
							return true, "", nil
						}
						return false, "", fmt.Errorf("failed to detect private IP: %v", err)
					}
					*hostIP = privateIP
				} else {
					publicIP, err := network.DetectPublicIP()
					if err != nil || publicIP == "" {
						privateIP, fallbackErr := network.DetectPrivateIP()
						if fallbackErr != nil {
							if isDone {
								return true, "", nil
							}
							return false, "", fmt.Errorf("failed to detect any IP: %v", fallbackErr)
						}
						*hostIP = privateIP
					} else {
						*hostIP = publicIP
					}
				}
				os.Setenv("TGUARD_HOST_IP", *hostIP)

				if isDone {
					return true, "", nil
				}
				return false, fmt.Sprintf("ℹ Host IP: %s", *hostIP), nil
			},
		},
		{
			Key:   "docker",
			Title: "Ensuring Docker Engine is Running",
			Action: func() (bool, string, error) {
				isDone := state.IsStepDone("docker")
				if !isDone {
					if err := docker.EnsureDaemon(); err != nil {
						return false, "", fmt.Errorf("docker engine failure: %v", err)
					}
				}
				var errPaths error
				*paths, errPaths = env.InitPaths()
				if errPaths != nil {
					return isDone, "", fmt.Errorf("failed to resolve paths: %v", errPaths)
				}

				*wazuhDir = filepath.Join((*paths).RootDir, "wazuh-docker", "single-node")

				if *hostIP == "" {
					*hostIP = os.Getenv("TGUARD_HOST_IP")
				}
				if *hostIP == "" {
					if cfg.NetworkType == "Private Network" {
						*hostIP, _ = network.DetectPrivateIP()
					} else {
						*hostIP, _ = network.DetectPublicIP()
						if *hostIP == "" {
							*hostIP, _ = network.DetectPrivateIP()
						}
					}
				}

				return isDone, "", nil
			},
		},
	}

	if cfg.UseVirusTotal && cfg.VTAPIKey != "" {
		steps = append(steps, &Step{
			Key:   "virustotal",
			Title: "Injecting VirusTotal API Key into Wazuh Config",
			Action: func() (bool, string, error) {
				if state.IsStepDone("virustotal") {
					return true, "", nil
				}
				if err := injectVirusTotalKey(*wazuhDir, cfg.VTAPIKey); err != nil {
					return false, "", err
				}
				return false, "", nil
			},
		})
	}

	steps = append(steps, &Step{
		Key:   "certs",
		Title: "Generating Wazuh Indexer Certificates",
		Action: func() (bool, string, error) {
			if state.IsStepDone("certs") {
				// Verify if the certificates actually exist on disk AND are not directories
				certFile := filepath.Join(*wazuhDir, "config", "wazuh_indexer_ssl_certs", "admin.pem")
				if stat, err := os.Stat(certFile); err == nil && !stat.IsDir() {
					return true, "", nil
				}
			}
			cmd := exec.Command("sudo", "docker", "compose", "-f", "generate-indexer-certs.yml", "run", "--rm", "generator")
			cmd.Dir = *wazuhDir
			out, runErr := cmd.CombinedOutput()
			if runErr != nil {
				cmdV1 := exec.Command("sudo", "docker-compose", "-f", "generate-indexer-certs.yml", "run", "--rm", "generator")
				cmdV1.Dir = *wazuhDir
				outV1, runErrV1 := cmdV1.CombinedOutput()
				if runErrV1 != nil {
					return false, "", fmt.Errorf("certificate generation failed:\n%s\n%s", string(out), string(outV1))
				}
			}
			return false, "", nil
		},
	})

	steps = append(steps, &Step{
		Key:   "wazuh",
		Title: "Deploying Wazuh SIEM",
		Action: func() (bool, string, error) {
			if state.IsStepDone("wazuh") {
				return true, "", nil
			}
			if err := docker.ComposeUp(*wazuhDir); err != nil {
				return false, "", fmt.Errorf("wazuh deployment failed: %v", err)
			}
			return false, "", nil
		},
	})

	steps = append(steps, &Step{
		Key:   "wazuh_agent",
		Title: "Installing Wazuh Agent (Local Host)",
		Action: func() (bool, string, error) {
			if state.IsStepDone("wazuh_agent") {
				return true, "", nil
			}

			const (
				gpgTimeout     = 3 * time.Minute  // allow for slow connections
				aptTimeout     = 20 * time.Minute // large package + slow mirror
				serviceTimeout = 45 * time.Second // systemctl should not take long
			)

			// ── 1. Download GPG key ───────────────────────────────────────
			ctx, cancel := context.WithTimeout(context.Background(), gpgTimeout)
			curlCmd := exec.CommandContext(ctx, "curl", "-s", "--fail",
				"https://packages.wazuh.com/key/GPG-KEY-WAZUH")
			keyBytes, err := curlCmd.Output()
			cancel()
			if err != nil {
				if ctx.Err() == context.DeadlineExceeded {
					return false, "", fmt.Errorf("wazuh GPG key download timed out (check internet connection)")
				}
				return false, "", fmt.Errorf("failed to download Wazuh GPG key: %w", err)
			}
			if len(keyBytes) == 0 {
				return false, "", fmt.Errorf("wazuh GPG key download returned empty response")
			}

			// ── 2. Import GPG key ─────────────────────────────────────────
			gpgCtx, gpgCancel := context.WithTimeout(context.Background(), gpgTimeout)
			gpgCmd := exec.CommandContext(gpgCtx, "gpg",
				"--no-default-keyring",
				"--keyring", "gnupg-ring:/usr/share/keyrings/wazuh.gpg",
				"--import")
			gpgCmd.Stdin = strings.NewReader(string(keyBytes))
			if out, err := gpgCmd.CombinedOutput(); err != nil {
				gpgCancel()
				if gpgCtx.Err() == context.DeadlineExceeded {
					return false, "", fmt.Errorf("GPG import timed out")
				}
				return false, "", fmt.Errorf("failed to import Wazuh GPG key: %w\n%s", err, string(out))
			}
			gpgCancel()

			// Set permission key
			if err := os.Chmod("/usr/share/keyrings/wazuh.gpg", 0644); err != nil {
				return false, "", fmt.Errorf("failed to set GPG key permissions: %w", err)
			}

			// ── 3. Tambahkan repository ───────────────────────────────────
			repoLine := "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main\n"
			repoFile := "/etc/apt/sources.list.d/wazuh.list"
			if err := os.WriteFile(repoFile, []byte(repoLine), 0644); err != nil {
				return false, "", fmt.Errorf("failed to write Wazuh apt repository: %w", err)
			}

			// ── 4. apt-get update ─────────────────────────────────────────
			aptCtx, aptCancel := context.WithTimeout(context.Background(), aptTimeout)
			aptUpdate := exec.CommandContext(aptCtx, "apt-get", "update", "-qq")
			if out, err := aptUpdate.CombinedOutput(); err != nil {
				aptCancel()
				if aptCtx.Err() == context.DeadlineExceeded {
					return false, "", fmt.Errorf("apt-get update timed out after %v (check network connectivity)", aptTimeout)
				}
				return false, "", fmt.Errorf("apt-get update failed: %w\n%s", err, strings.TrimSpace(string(out)))
			}
			aptCancel()

			// ── 5. Install wazuh-agent ────────────────────────────────────
			managerIP := *hostIP
			if managerIP == "" {
				managerIP = "127.0.0.1"
			}

			installCtx, installCancel := context.WithTimeout(context.Background(), aptTimeout)
			installEnv := append(os.Environ(), fmt.Sprintf("WAZUH_MANAGER=%s", managerIP))
			installCmd := exec.CommandContext(installCtx, "apt-get", "install", "-y", "-qq", "wazuh-agent")
			installCmd.Env = installEnv
			if out, err := installCmd.CombinedOutput(); err != nil {
				installCancel()
				if installCtx.Err() == context.DeadlineExceeded {
					return false, "", fmt.Errorf("wazuh-agent installation timed out")
				}
				return false, "", fmt.Errorf("failed to install wazuh-agent: %w\n%s", err, string(out))
			}
			installCancel()

			// ── 5.1 Inject PoC Directory to Wazuh Agent syscheck ──────────
			paths, _ := env.InitPaths()
			pocDir := filepath.Join(paths.RootDir, "usecase", "webdeface")
			
			// Ensure the directory exists so FIM doesn't complain
			os.MkdirAll(pocDir, 0755)

			agentConf := "/var/ossec/etc/ossec.conf"
			if confData, err := os.ReadFile(agentConf); err == nil {
				confStr := string(confData)
				injectStr := fmt.Sprintf("\n    <directories realtime=\"yes\">%s</directories>\n", pocDir)
				
				// Ensure Manager IP is correct
				// We use regex to replace whatever IP is in <address>...</address> just in case it was installed previously
				ipRegex := regexp.MustCompile(`(<client>\s*<server>\s*<address>)[^<]+(</address>)`)
				if ipRegex.MatchString(confStr) {
					confStr = ipRegex.ReplaceAllString(confStr, "${1}"+managerIP+"${2}")
				}

				// Inject just after <syscheck> tag
				if !strings.Contains(confStr, pocDir) {
					confStr = strings.Replace(confStr, "<syscheck>", "<syscheck>"+injectStr, 1)
					os.WriteFile(agentConf, []byte(confStr), 0644)
				}
			}

			// ── 6. Enable dan start service ───────────────────────────────
			type svcCmd struct {
				args []string
				desc string
			}
			svcCmds := []svcCmd{
				{[]string{"systemctl", "daemon-reload"}, "daemon-reload"},
				{[]string{"systemctl", "enable", "wazuh-agent"}, "enable wazuh-agent"},
				{[]string{"systemctl", "start", "wazuh-agent"}, "start wazuh-agent"},
			}

			var svcWarnings []string
			for _, sc := range svcCmds {
				svcCtx, svcCancel := context.WithTimeout(context.Background(), serviceTimeout)
				out, err := exec.CommandContext(svcCtx, sc.args[0], sc.args[1:]...).CombinedOutput()
				svcCancel()
				if err != nil {
					if svcCtx.Err() == context.DeadlineExceeded {
						svcWarnings = append(svcWarnings, fmt.Sprintf("⚠ %s timed out (non-fatal)", sc.desc))
					} else {
						svcWarnings = append(svcWarnings, fmt.Sprintf("⚠ %s: %s", sc.desc, strings.TrimSpace(string(out))))
					}
				}
			}

			logMsg := fmt.Sprintf("Wazuh Agent installed — Manager: %s", managerIP)
			if len(svcWarnings) > 0 {
				logMsg += "\n" + strings.Join(svcWarnings, "\n")
			}
			return false, logMsg, nil
		},
	})

	if cfg.SOAREngine == "n8n" {
		steps = append(steps, &Step{
			Key:   "n8n",
			Title: "Deploying n8n (SOAR Engine)",
			Action: func() (bool, string, error) {
				if state.IsStepDone("n8n") {
					return true, "", nil
				}
				n8nDir := filepath.Join((*paths).RootDir, "n8n")
				if err := docker.ComposeUp(n8nDir); err != nil {
					return false, "", fmt.Errorf("n8n deployment failed: %v", err)
				}
				return false, "", nil
			},
		})

		steps = append(steps, &Step{
			Key:   "n8n_workflow",
			Title: "Injecting T-Guard Workflow into n8n",
			Action: func() (bool, string, error) {
				if state.IsStepDone("n8n_workflow") {
					return true, "", nil
				}
				wflowPath := filepath.Join((*paths).RootDir, "n8n", "templates", "tguard-workflow.json")
				if _, err := os.Stat(wflowPath); err == nil {
					if err := InjectN8nWorkflow(wflowPath, "http://localhost:5678", ""); err != nil {
						return false, "⚠ Workflow injection failed (non-fatal). Inject manually via n8n UI.", nil
					}
				}
				return false, "", nil
			},
		})
	} else if cfg.SOAREngine == "Shuffle" {
		steps = append(steps, &Step{
			Key:   "shuffle",
			Title: "Deploying Shuffle (SOAR Engine)",
			Action: func() (bool, string, error) {
				if state.IsStepDone("shuffle") {
					return true, "", nil
				}
				shuffleDir := filepath.Join((*paths).RootDir, "shuffle")
				if err := docker.ComposeUp(shuffleDir); err != nil {
					return false, "", fmt.Errorf("shuffle deployment failed: %v", err)
				}
				return false, "", nil
			},
		})
	}

	if cfg.AdvancedMode {
		steps = append(steps, &Step{
			Key:   "advanced_mode",
			Title: "Advanced Mode Configuration",
			Action: func() (bool, string, error) {
				if state.IsStepDone("advanced_mode") {
					return true, "", nil
				}
				log := fmt.Sprintf("┌─ Advanced Mode Active ─────────────────────────────────┐\n│ Edit the following files to customize your deployment:\n│ Wazuh config : %s\n│ n8n/Shuffle  : %s\n└───────────────────────────────────────────────────────┘", filepath.Join(*wazuhDir, "docker-compose.yml"), filepath.Join((*paths).RootDir, strings.ToLower(cfg.SOAREngine)))
				return false, log, nil
			},
		})
	}

	return steps
}

// RunDeployment mengelola alur instalasi penuh
func RunDeployment(cfg Config) error {
	var (
		hw       *hardware.ServerHardware
		hostIP   string
		paths    *env.InstallerPaths
		wazuhDir string
	)

	steps := buildDeploymentSteps(cfg, &hw, &hostIP, &paths, &wazuhDir)

	p := tea.NewProgram(initialModel(steps), tea.WithAltScreen())
	m, err := p.Run()
	if err != nil {
		return err
	}

	uiModel := m.(InstallUI)
	if uiModel.Err != nil {
		return uiModel.Err
	}

	PrintSummary(cfg, hostIP, wazuhDir)
	return nil
}
func injectVirusTotalKey(wazuhDir, apiKey string) error {
	managerConf := filepath.Join(wazuhDir, "config", "wazuh_cluster", "wazuh_manager.conf")

	managerData, err := os.ReadFile(managerConf)
	if err != nil {
		return fmt.Errorf("failed to read wazuh_manager.conf: %v", err)
	}

	content := string(managerData)
	
	// Use regex to replace api_key inside virustotal integration block
	pattern := `(?s)(<integration>.*?<name>virustotal</name>.*?<api_key>)[^<]+(</api_key>.*?</integration>)`
	re := regexp.MustCompile(pattern)
	
	if re.MatchString(content) {
		content = re.ReplaceAllString(content, "${1}"+apiKey+"${2}")
	}

	if err := os.WriteFile(managerConf, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write wazuh_manager.conf: %v", err)
	}
	return nil
}



// PrintSummary menampilkan ringkasan post-install dengan URL dan kredensial lengkap
func PrintSummary(cfg Config, hostIP string, wazuhDir string) {
	fmt.Println()

	boxStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#00e5ff")).
		Padding(1, 3).
		MarginTop(1)

	titleStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#00e5ff")).Bold(true).Underline(true)
	sectionStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#0077ff")).Bold(true)
	labelStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#6b7280"))
	valStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#10b981")).Bold(true)
	warnStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#fbbf24")).Bold(true)
	dimStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#4b5563"))

	// Baca credential langsung dari docker-compose.yml Wazuh
	wazuhCreds := readWazuhCredentials(wazuhDir)

	var sb strings.Builder
	sb.WriteString(titleStyle.Render("T-Guard Deployment Complete!") + "\n\n")

	// ── Wazuh Dashboard ─────────────────────────────────────
	sb.WriteString(sectionStyle.Render("[ Wazuh Dashboard (SIEM) ]") + "\n")
	sb.WriteString("  " + labelStyle.Render("URL          : ") + valStyle.Render(fmt.Sprintf("https://%s", hostIP)) + "\n")
	sb.WriteString("  " + labelStyle.Render("Port         : ") + valStyle.Render("443") + "\n")
	sb.WriteString("  " + labelStyle.Render("Username     : ") + valStyle.Render(wazuhCreds.IndexerUser) + "\n")
	sb.WriteString("  " + labelStyle.Render("Password     : ") + valStyle.Render(wazuhCreds.IndexerPass) + "\n\n")

	// ── Wazuh API ────────────────────────────────────────────
	sb.WriteString(sectionStyle.Render("[ Wazuh REST API ]") + "\n")
	sb.WriteString("  " + labelStyle.Render("URL          : ") + valStyle.Render(fmt.Sprintf("https://%s:55000", hostIP)) + "\n")
	sb.WriteString("  " + labelStyle.Render("Username     : ") + valStyle.Render(wazuhCreds.APIUser) + "\n")
	sb.WriteString("  " + labelStyle.Render("Password     : ") + valStyle.Render(wazuhCreds.APIPass) + "\n\n")

	// ── Wazuh Indexer (OpenSearch) ───────────────────────────
	sb.WriteString(sectionStyle.Render("[ Wazuh Indexer (OpenSearch) ]") + "\n")
	sb.WriteString("  " + labelStyle.Render("URL          : ") + valStyle.Render(fmt.Sprintf("https://%s:9200", hostIP)) + "\n")
	sb.WriteString("  " + labelStyle.Render("Username     : ") + valStyle.Render(wazuhCreds.IndexerUser) + "\n")
	sb.WriteString("  " + labelStyle.Render("Password     : ") + valStyle.Render(wazuhCreds.IndexerPass) + "\n\n")

	// ── SOAR Engine ──────────────────────────────────────────
	sb.WriteString(sectionStyle.Render(fmt.Sprintf("[ SOAR Engine: %s ]", cfg.SOAREngine)) + "\n")
	switch cfg.SOAREngine {
	case "n8n":
		sb.WriteString("  " + labelStyle.Render("URL          : ") + valStyle.Render(fmt.Sprintf("http://%s:5678", hostIP)) + "\n")
		sb.WriteString("  " + labelStyle.Render("Credentials  : ") + dimStyle.Render("Create account on first visit") + "\n\n")
	case "Shuffle":
		sb.WriteString("  " + labelStyle.Render("URL          : ") + valStyle.Render(fmt.Sprintf("http://%s:3001", hostIP)) + "\n")
		sb.WriteString("  " + labelStyle.Render("Credentials  : ") + dimStyle.Render("Create account on first visit") + "\n\n")
	}

	// ── DFIR-IRIS ────────────────────────────────────────────
	sb.WriteString(sectionStyle.Render("[ DFIR-IRIS ]") + "\n")
	sb.WriteString("  " + labelStyle.Render("URL          : ") + valStyle.Render(fmt.Sprintf("https://%s:8443", hostIP)) + "\n")
	sb.WriteString("  " + labelStyle.Render("Username     : ") + valStyle.Render("administrator") + "\n")
	sb.WriteString("  " + labelStyle.Render("Password     : ") + valStyle.Render("MySuperAdminPassword!") + "\n\n")

	// ── MISP ─────────────────────────────────────────────────
	sb.WriteString(sectionStyle.Render("[ MISP ]") + "\n")
	sb.WriteString("  " + labelStyle.Render("URL          : ") + valStyle.Render(fmt.Sprintf("https://%s:1443", hostIP)) + "\n")
	sb.WriteString("  " + labelStyle.Render("Username     : ") + valStyle.Render("admin@admin.test") + "\n")
	sb.WriteString("  " + labelStyle.Render("Password     : ") + valStyle.Render("admin") + "\n\n")

	// ── Wazuh Agent ──────────────────────────────────────────
	sb.WriteString(sectionStyle.Render("[ Wazuh Agent Registration ]") + "\n")
	sb.WriteString("  " + labelStyle.Render("Manager IP   : ") + valStyle.Render(hostIP) + "\n")
	sb.WriteString("  " + labelStyle.Render("Port         : ") + valStyle.Render("1514 (tcp) | 1515 (enrollment)") + "\n\n")

	// ── VirusTotal ───────────────────────────────────────────
	if cfg.UseVirusTotal {
		sb.WriteString(sectionStyle.Render("[ VirusTotal Integration ]") + "\n")
		sb.WriteString("  " + valStyle.Render("✔ API Key injected into Wazuh config") + "\n\n")
	}

	// ── Security Reminder ────────────────────────────────────
	sb.WriteString(warnStyle.Render("! SECURITY REMINDER:") + "\n")
	sb.WriteString("  " + dimStyle.Render("• Change default Wazuh passwords above immediately!") + "\n")
	sb.WriteString("  " + dimStyle.Render("• Enable firewall: sudo ufw enable") + "\n")
	sb.WriteString("  " + dimStyle.Render("• Allow only trusted IPs on ports 443, 5678, 9200, 55000") + "\n")

	fmt.Println(boxStyle.Render(sb.String()))

	// ── Useful Commands ──────────────────────────────────────
	quickLabelStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#6b7280"))
	quickDimStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#4b5563"))
	fmt.Println(quickLabelStyle.Render("  Quick Commands:"))
	fmt.Printf("  %s sudo docker compose -f %s ps\n",
		quickDimStyle.Render("Status  →"),
		filepath.Join(wazuhDir, "docker-compose.yml"))
	fmt.Printf("  %s sudo docker compose -f %s logs -f\n",
		quickDimStyle.Render("Logs    →"),
		filepath.Join(wazuhDir, "docker-compose.yml"))
	fmt.Printf("  %s sudo docker compose -f %s down\n",
		quickDimStyle.Render("Stop    →"),
		filepath.Join(wazuhDir, "docker-compose.yml"))
	fmt.Println()
}

// WazuhCredentials menyimpan credential yang dibaca dari docker-compose.yml
type WazuhCredentials struct {
	IndexerUser string
	IndexerPass string
	APIUser     string
	APIPass     string
}

// readWazuhCredentials membaca credential langsung dari file docker-compose.yml Wazuh
func readWazuhCredentials(wazuhDir string) WazuhCredentials {
	creds := WazuhCredentials{
		// Default fallback jika parsing gagal
		IndexerUser: "admin",
		IndexerPass: "SecretPassword",
		APIUser:     "wazuh-wui",
		APIPass:     "MyS3cr37P450r.*-",
	}

	data, err := os.ReadFile(filepath.Join(wazuhDir, "docker-compose.yml"))
	if err != nil {
		return creds
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "- INDEXER_USERNAME=") {
			creds.IndexerUser = strings.TrimPrefix(line, "- INDEXER_USERNAME=")
		} else if strings.HasPrefix(line, "- INDEXER_PASSWORD=") {
			creds.IndexerPass = strings.TrimPrefix(line, "- INDEXER_PASSWORD=")
		} else if strings.HasPrefix(line, "- API_USERNAME=") {
			creds.APIUser = strings.TrimPrefix(line, "- API_USERNAME=")
		} else if strings.HasPrefix(line, "- API_PASSWORD=") {
			creds.APIPass = strings.TrimPrefix(line, "- API_PASSWORD=")
		}
	}
	return creds
}

// InjectWazuhScripts copies integration scripts into the running Wazuh container and sets permissions.
func InjectWazuhScripts(rootDir string) error {
	wazuhDir := filepath.Join(rootDir, "wazuh-docker", "single-node")
	integrationsDir := filepath.Join(wazuhDir, "custom-integrations")
	
	// Copy local_rules.xml
	exec.Command("sudo", "docker", "cp", filepath.Join(integrationsDir, "local_rules.xml"), "single-node-wazuh.manager-1:/var/ossec/etc/rules/").Run()
	exec.Command("sudo", "docker", "exec", "-u", "root", "single-node-wazuh.manager-1", "chown", "wazuh:wazuh", "/var/ossec/etc/rules/local_rules.xml").Run()
	exec.Command("sudo", "docker", "exec", "-u", "root", "single-node-wazuh.manager-1", "chmod", "660", "/var/ossec/etc/rules/local_rules.xml").Run()

	// Copy integration scripts
	scripts := []string{"custom-iris.py", "custom-misp.py", "custom-misp", "custom-n8n.py", "custom-wazuh_iris.py"}
	for _, script := range scripts {
		src := filepath.Join(integrationsDir, script)
		dest := "/var/ossec/integrations/" + script
		exec.Command("sudo", "docker", "cp", src, "single-node-wazuh.manager-1:"+dest).Run()
		exec.Command("sudo", "docker", "exec", "-u", "root", "single-node-wazuh.manager-1", "chown", "root:wazuh", dest).Run()
		exec.Command("sudo", "docker", "exec", "-u", "root", "single-node-wazuh.manager-1", "chmod", "750", dest).Run()
	}

	// Copy active response script
	arSrc := filepath.Join(integrationsDir, "remove-threat.sh")
	arDest := "/var/ossec/active-response/bin/remove-threat.sh"
	exec.Command("sudo", "docker", "cp", arSrc, "single-node-wazuh.manager-1:"+arDest).Run()
	exec.Command("sudo", "docker", "exec", "-u", "root", "single-node-wazuh.manager-1", "chown", "root:wazuh", arDest).Run()
	exec.Command("sudo", "docker", "exec", "-u", "root", "single-node-wazuh.manager-1", "chmod", "750", arDest).Run()

	// Restart Wazuh Manager
	exec.Command("sudo", "docker", "exec", "-u", "root", "single-node-wazuh.manager-1", "/var/ossec/bin/wazuh-control", "restart").Run()
	
	return nil
}

// Waktu tunggu lain diperlukan untuk n8n
const n8nReadyTimeout = 90 * time.Second
