package orchestration

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/charmbracelet/lipgloss"
	tea "github.com/charmbracelet/bubbletea"
	"tguard-installer/pkg/env"
)

const integrationStateDir = "/var/lib/tguard_state"
const integrationStateFile = integrationStateDir + "/integration.json"

// IntegrationConfig holds all URLs and credentials for manual integration mode.
type IntegrationConfig struct {
	IRISURL       string `json:"iris_url"`
	IRISAPIKey    string `json:"iris_api_key"`
	MISPURL       string `json:"misp_url"`
	MISPAPIKey    string `json:"misp_api_key"`
	N8nURL        string `json:"n8n_url"`
	VTAPIKey      string `json:"vt_api_key"`
}

// RunIntegration saves all integration credentials to disk and prints a summary.
func RunIntegration(cfg IntegrationConfig) error {
	steps := []*Step{
		{
			Key:   "save_integration_config",
			Title: "Saving Integration Configuration",
			Action: func() (bool, string, error) {
				if err := os.MkdirAll(integrationStateDir, 0700); err != nil {
					return false, "", fmt.Errorf("failed to create state dir %s: %v\n  Hint: run as root or with sudo", integrationStateDir, err)
				}

				data, err := json.MarshalIndent(cfg, "", "  ")
				if err != nil {
					return false, "", fmt.Errorf("failed to marshal integration config: %v", err)
				}

				if err := os.WriteFile(integrationStateFile, data, 0600); err != nil {
					return false, "", fmt.Errorf("failed to write integration config to %s: %v", integrationStateFile, err)
				}

				// --- AUTO-INJECT INTO WAZUH SCRIPTS ---
				paths, _ := env.InitPaths()
				wazuhIntegrationsDir := filepath.Join(paths.RootDir, "wazuh-docker", "single-node", "custom-integrations")
				
				// 1. Inject MISP API Key into custom-misp.py
				mispScript := filepath.Join(wazuhIntegrationsDir, "custom-misp.py")
				if mispData, err := os.ReadFile(mispScript); err == nil {
					content := string(mispData)
					apiRegex := regexp.MustCompile(`(misp_api_auth_key\s*=\s*")[^"]+(")`)
					if apiRegex.MatchString(content) {
						content = apiRegex.ReplaceAllString(content, "${1}"+cfg.MISPAPIKey+"${2}")
					}
					urlRegex := regexp.MustCompile(`(misp_base_url\s*=\s*")[^"]+(")`)
					if strings.Contains(cfg.MISPURL, "://") && urlRegex.MatchString(content) {
						content = urlRegex.ReplaceAllString(content, "${1}"+cfg.MISPURL+"/attributes/restSearch/${2}")
					}
					os.WriteFile(mispScript, []byte(content), 0755)
				}

				// 2. Inject API Keys and URLs into wazuh_manager.conf
				managerConf := filepath.Join(paths.RootDir, "wazuh-docker", "single-node", "config", "wazuh_cluster", "wazuh_manager.conf")
				if managerData, err := os.ReadFile(managerConf); err == nil {
					content := string(managerData)
					
					// Function to replace tags specifically inside a given integration block
					replaceInIntegration := func(config, integrationName, tagName, newValue string) string {
						// (?s) makes . match newline. We find <integration> ... <name>integrationName</name> ... </integration>
						// and replace <tagName>...</tagName> within it.
						// This regex matches the block, captures parts around the tag, and rebuilds it.
						pattern := fmt.Sprintf(`(?s)(<integration>.*?<name>%s</name>.*?<%s>)[^<]+(</%s>.*?</integration>)`, integrationName, tagName, tagName)
						re := regexp.MustCompile(pattern)
						return re.ReplaceAllString(config, "${1}"+newValue+"${2}")
					}

					if cfg.IRISAPIKey != "" {
						content = replaceInIntegration(content, "custom-wazuh_iris.py", "api_key", cfg.IRISAPIKey)
					}
					if strings.Contains(cfg.IRISURL, "://") {
						content = replaceInIntegration(content, "custom-wazuh_iris.py", "hook_url", cfg.IRISURL+"/alerts/add")
					}
					if strings.Contains(cfg.N8nURL, "://") {
						// Wait, N8N webhook ID is needed? Currently the installer just assumes WEBHOOK_ID is part of URL or we just replace the whole URL.
						// Let's replace the whole N8N url. The user inputs the full webhook URL in N8nURL.
						content = replaceInIntegration(content, "custom-n8n.py", "hook_url", cfg.N8nURL)
					}
					if cfg.VTAPIKey != "" {
						content = replaceInIntegration(content, "virustotal", "api_key", cfg.VTAPIKey)
					}

					os.WriteFile(managerConf, []byte(content), 0644)
				}
				// ---------------------------------------
				
				// Apply to running Wazuh container
				InjectWazuhScripts(paths.RootDir)
				
				return false, "Integration config saved and injected into Wazuh successfully.", nil
			},
		},
	}

	p := tea.NewProgram(initialModel(steps), tea.WithAltScreen())
	m, err := p.Run()
	if err != nil {
		return err
	}

	uiModel := m.(InstallUI)
	if uiModel.Err != nil {
		return uiModel.Err
	}

	sectionStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#0077ff")).Bold(true)
	labelStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#6b7280"))
	valStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#10b981")).Bold(true)
	warnStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#fbbf24")).Bold(true)
	dimStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#4b5563"))
	greenStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#10b981"))
	boxStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#00e5ff")).
		Padding(1, 3).
		MarginTop(1)

	var sb strings.Builder

	sb.WriteString(sectionStyle.Render("[ IRIS DFIR ]") + "\n")
	sb.WriteString("  " + labelStyle.Render("URL      : ") + valStyle.Render(cfg.IRISURL) + "\n")
	sb.WriteString("  " + labelStyle.Render("API Key  : ") + dimStyle.Render("saved (hidden)") + "\n\n")

	sb.WriteString(sectionStyle.Render("[ MISP Threat Intel ]") + "\n")
	sb.WriteString("  " + labelStyle.Render("URL      : ") + valStyle.Render(cfg.MISPURL) + "\n")
	sb.WriteString("  " + labelStyle.Render("API Key  : ") + dimStyle.Render("saved (hidden)") + "\n\n")

	sb.WriteString(sectionStyle.Render("[ n8n SOAR ]") + "\n")
	sb.WriteString("  " + labelStyle.Render("URL      : ") + valStyle.Render(cfg.N8nURL) + "\n\n")

	if cfg.VTAPIKey != "" {
		sb.WriteString(sectionStyle.Render("[ VirusTotal ]") + "\n")
		sb.WriteString("  " + labelStyle.Render("API Key  : ") + dimStyle.Render("saved (hidden)") + "\n\n")
	}

	sb.WriteString(warnStyle.Render("Config saved to: ") + dimStyle.Render(filepath.Clean(integrationStateFile)) + "\n")

	content := boxStyle.Render(sb.String()) + "\n" +
		greenStyle.Render("  [✔] Integration configuration saved successfully.") + "\n" +
		dimStyle.Render("  [ℹ] API integrations will be applied on next T-Guard service restart.")

	if uiModel.Width > 0 {
		fmt.Print(lipgloss.PlaceHorizontal(uiModel.Width, lipgloss.Center, content))
	} else {
		fmt.Println(content)
	}
	fmt.Println()

	return nil
}
