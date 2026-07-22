package orchestration

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"tguard-installer/pkg/docker"
	"tguard-installer/pkg/env"
	"tguard-installer/pkg/hardware"
	"tguard-installer/pkg/network"
	"tguard-installer/pkg/state"
)

// detectHostIP returns the host IP based on network config or env var.
func detectHostIP(cfg Config) string {
	ip := os.Getenv("TGUARD_HOST_IP")
	if ip != "" {
		return ip
	}
	if cfg.NetworkType == "Private Network" {
		ip, _ = network.DetectPrivateIP()
	} else {
		ip, _ = network.DetectPublicIP()
		if ip == "" {
			ip, _ = network.DetectPrivateIP()
		}
	}
	return ip
}

// RunFullInstall orchestrates the complete T-Guard stack:
// Wazuh SIEM + SOAR (n8n or Shuffle) + IRIS DFIR + MISP Threat Intel.
func RunFullInstall(cfg Config) error {
	var (
		hw       *hardware.ServerHardware
		hostIP   string
		paths    *env.InstallerPaths
		wazuhDir string
	)

	steps := buildDeploymentSteps(cfg, &hw, &hostIP, &paths, &wazuhDir)

	// Appending full install steps
	steps = append(steps, &Step{
		Key:   "iris",
		Title: "Deploying IRIS DFIR Platform",
		Action: func() (bool, string, error) {
			if state.IsStepDone("iris") {
				return true, "", nil
			}
			irisDir := filepath.Join((*paths).RootDir, "iris-web")
			if err := docker.ComposeUp(irisDir); err != nil {
				return false, "", fmt.Errorf("IRIS deployment failed: %v", err)
			}
			return false, "", nil
		},
	})


	steps = append(steps, &Step{
		Key:   "misp",
		Title: "Deploying MISP Threat Intel Platform",
		Action: func() (bool, string, error) {
			if state.IsStepDone("misp") {
				return true, "", nil
			}
			mispDir := filepath.Join((*paths).RootDir, "misp-docker")
			mispEnvPath := filepath.Join(mispDir, ".env")
			if _, err := os.Stat(mispEnvPath); os.IsNotExist(err) {
				templateEnv := filepath.Join(mispDir, "template.env")
				input, err := os.ReadFile(templateEnv)
				if err != nil {
					return false, "", fmt.Errorf("failed to read MISP template.env: %v", err)
				}
				
				// Inject BASE_URL dynamically
				content := string(input)
				content = strings.Replace(content, "BASE_URL='https://localhost'", fmt.Sprintf("BASE_URL='https://%s:1443'", hostIP), 1)

				if err := os.WriteFile(mispEnvPath, []byte(content), 0644); err != nil {
					return false, "", fmt.Errorf("failed to write MISP .env: %v", err)
				}
			}

			if err := docker.ComposeUp(mispDir); err != nil {
				return false, "", fmt.Errorf("MISP deployment failed: %v", err)
			}
			return false, "", nil
		},
	})

	p := tea.NewProgram(initialModel(steps), tea.WithAltScreen())
	m, err := p.Run()
	if err != nil {
		return err
	}

	uiModel := m.(InstallUI)
	if uiModel.Err != nil {
		return uiModel.Err
	}

	irisDir := filepath.Join((*paths).RootDir, "iris-web")
	
	// Ensure Wazuh scripts and integrations are properly injected and have correct permissions
	InjectWazuhScripts((*paths).RootDir)
	
	printFullSummary(cfg, hostIP, wazuhDir, irisDir, uiModel.Width, uiModel.Height)
	return nil
}
func printFullSummary(cfg Config, hostIP, wazuhDir, irisDir string, width, height int) {
	fmt.Println()
	_ = irisDir // reserved for future .env re-reading

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

	wazuhCreds := readWazuhCredentials(wazuhDir)

	var sb strings.Builder
	sb.WriteString(titleStyle.Render("T-Guard Full Stack Deployment Complete!") + "\n\n")

	// ── Wazuh Dashboard ──────────────────────────────────────────────────────
	sb.WriteString(sectionStyle.Render("[ Wazuh Dashboard (SIEM) ]") + "\n")
	sb.WriteString("  " + labelStyle.Render("URL          : ") + valStyle.Render(fmt.Sprintf("https://%s", hostIP)) + "\n")
	sb.WriteString("  " + labelStyle.Render("Port         : ") + valStyle.Render("443") + "\n")
	sb.WriteString("  " + labelStyle.Render("Username     : ") + valStyle.Render(wazuhCreds.IndexerUser) + "\n")
	sb.WriteString("  " + labelStyle.Render("Password     : ") + valStyle.Render(wazuhCreds.IndexerPass) + "\n\n")



	// ── SOAR Engine ──────────────────────────────────────────────────────────
	sb.WriteString(sectionStyle.Render(fmt.Sprintf("[ SOAR Engine: %s ]", cfg.SOAREngine)) + "\n")
	switch cfg.SOAREngine {
	case "n8n":
		sb.WriteString("  " + labelStyle.Render("URL          : ") + valStyle.Render(fmt.Sprintf("http://%s:5678", hostIP)) + "\n")
		sb.WriteString("  " + labelStyle.Render("Credentials  : ") + dimStyle.Render("Create account on first visit") + "\n\n")
	case "Shuffle":
		sb.WriteString("  " + labelStyle.Render("URL          : ") + valStyle.Render(fmt.Sprintf("http://%s:3001", hostIP)) + "\n")
		sb.WriteString("  " + labelStyle.Render("Credentials  : ") + dimStyle.Render("Create account on first visit") + "\n\n")
	}

	// ── IRIS DFIR ─────────────────────────────────────────────────────────────
	sb.WriteString(sectionStyle.Render("[ IRIS DFIR Platform ]") + "\n")
	sb.WriteString("  " + labelStyle.Render("URL          : ") + valStyle.Render(fmt.Sprintf("https://%s:8443", hostIP)) + "\n")
	sb.WriteString("  " + labelStyle.Render("Username     : ") + valStyle.Render("administrator") + "\n")
	sb.WriteString("  " + labelStyle.Render("Password     : ") + valStyle.Render("MySuperAdminPassword!") + "\n\n")

	// ── MISP ─────────────────────────────────────────────────────────────────
	sb.WriteString(sectionStyle.Render("[ MISP Threat Intelligence ]") + "\n")
	sb.WriteString("  " + labelStyle.Render("URL          : ") + valStyle.Render(fmt.Sprintf("https://%s:1443", hostIP)) + "\n")
	sb.WriteString("  " + labelStyle.Render("Username     : ") + valStyle.Render("admin@admin.test") + "\n")
	sb.WriteString("  " + labelStyle.Render("Password     : ") + valStyle.Render("admin  (change immediately!)") + "\n\n")



	// ── Security Reminder ─────────────────────────────────────────────────────
	sb.WriteString(warnStyle.Render("! SECURITY REMINDER:") + "\n")
	sb.WriteString("  " + dimStyle.Render("• Change ALL default passwords above immediately!") + "\n")
	sb.WriteString("  " + dimStyle.Render("• Enable firewall: sudo ufw enable") + "\n")
	sb.WriteString("  " + dimStyle.Render("• Restrict ports: 443, 1443, 5678, 8443, 9200, 55000") + "\n\n")

	// ── Next Steps ────────────────────────────────────────────────────────────
	sb.WriteString(sectionStyle.Render("🚀 NEXT STEPS (INTEGRATION):") + "\n")
	sb.WriteString("  " + dimStyle.Render("1. Log in to IRIS and MISP dashboards to generate your API keys.") + "\n")
	sb.WriteString("  " + dimStyle.Render("2. Run the installer again and choose ") + valStyle.Render("[2] Integrate Manual") + dimStyle.Render(".") + "\n")
	sb.WriteString("  " + dimStyle.Render("3. Follow the on-screen prompts to link all platforms to n8n.") + "\n")

	content := boxStyle.Render(sb.String())
	if width > 0 {
		fmt.Print(lipgloss.PlaceHorizontal(width, lipgloss.Center, content))
	} else {
		fmt.Println(content)
	}
	fmt.Println()
}
