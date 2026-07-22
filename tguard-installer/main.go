package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"tguard-installer/pkg/env"
	"tguard-installer/pkg/network"
	"tguard-installer/pkg/orchestration"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
)

// ── Colours ──────────────────────────────────────────────────────────────────
var (
	brandPrimary   = lipgloss.Color("#00e5ff") // Cyan Neon
	brandSecondary = lipgloss.Color("#0077ff") // Deep Blue
	textMuted      = lipgloss.Color("#6b7280") // Gray
	successColor   = lipgloss.Color("#10b981") // Emerald Green
	errorColor     = lipgloss.Color("#ef4444") // Red
)

// ── TUI Model ────────────────────────────────────────────────────────────────

type InstallerModel struct {
	form   *huh.Form
	width  int
	height int
	banner string
}

func (m InstallerModel) Init() tea.Cmd {
	return m.form.Init()
}

func (m InstallerModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		}
	}

	form, cmd := m.form.Update(msg)
	if f, ok := form.(*huh.Form); ok {
		m.form = f
	}

	if m.form.State == huh.StateCompleted || m.form.State == huh.StateAborted {
		return m, tea.Quit
	}

	return m, cmd
}

func (m InstallerModel) View() string {
	if m.width == 0 {
		return ""
	}

	bannerStyle := lipgloss.NewStyle().
		Foreground(brandPrimary).
		Bold(true).
		Align(lipgloss.Center)

	taglineStyle := lipgloss.NewStyle().
		Foreground(textMuted).
		Italic(true).
		Align(lipgloss.Center).
		MarginBottom(1)

	formBoxStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(brandSecondary).
		Padding(1, 4).
		MarginTop(1)

	bannerStr := bannerStyle.Render(m.banner)
	taglineStr := taglineStyle.Render("NEXT-GENERATION SECURITY OPERATIONS CENTER • v2.2")
	formStr := formBoxStyle.Render(m.form.View())

	content := lipgloss.JoinVertical(lipgloss.Center, bannerStr, taglineStr, formStr)
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, content)
}

// ── runForm runs a huh.Form inside the TUI model and returns whether it was completed ──
func runForm(form *huh.Form, banner string) bool {
	m := InstallerModel{form: form, banner: banner}
	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		log.Fatal(err)
	}
	return form.State == huh.StateCompleted
}

// ── Banner ───────────────────────────────────────────────────────────────────

const banner = `
 ████████╗       ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
 ╚══██╔══╝      ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
    ██║   █████╗██║  ███╗██║   ██║███████║██████╔╝██║  ██║
    ██║   ╚════╝██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
    ██║         ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
    ╚═╝          ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 
`

// ── Helpers ──────────────────────────────────────────────────────────────────

func abortMsg() {
	fmt.Println(lipgloss.NewStyle().Foreground(errorColor).Bold(true).Render(
		"\n[✖] Setup aborted. No changes were made to the system."))
	os.Exit(0)
}

func abortToMenu() {
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#fbbf24")).Bold(true).Render(
		"\n[!] Form aborted. Returning to main menu..."))
	main()
}

func printSummaryBox(title string, lines []string) {
	subTitle := lipgloss.NewStyle().Foreground(brandPrimary).Bold(true).Underline(true)
	border := lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()).
		BorderForeground(brandSecondary).
		Padding(1, 3).
		MarginTop(1).
		MarginBottom(1)

	var sb strings.Builder
	sb.WriteString(subTitle.Render(title) + "\n\n")
	for _, l := range lines {
		sb.WriteString(l + "\n")
	}
	fmt.Println(border.Render(sb.String()))
}

// ── Main ─────────────────────────────────────────────────────────────────────

func main() {
	// ── STEP 0: Main Menu ────────────────────────────────────────────────────
	var mainMode string
	mainForm := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("T-Guard — Main Menu").
				Description("Select an operation to perform.").
				Options(
					huh.NewOption("[1] Full Installation   — Install & integrate everything", "full"),
					huh.NewOption("[2] Integrate Manual   — Connect to existing services", "integrate"),
					huh.NewOption("[3] PoC (Proof of Concept) — Run security scenarios", "poc"),
					huh.NewOption("[4] Inject n8n Workflows — Load advanced SOC playbooks", "inject"),
					huh.NewOption("[5] View Default Credentials — Show default passwords", "creds"),
					huh.NewOption("[6] Uninstall          — Remove all T-Guard components", "uninstall"),
				).
				Value(&mainMode),
		),
	).WithTheme(huh.ThemeDracula())

	if !runForm(mainForm, banner) {
		abortMsg()
	}

	switch mainMode {
	case "full":
		runFullInstallFlow()
	case "integrate":
		runIntegrateFlow()
	case "poc":
		runPoCFlow()
	case "creds":
		runViewCredentialsFlow()
	case "uninstall":
		runUninstallFlow()
	case "inject":
		runInjectFlow()
	}
}

// ── Full Installation Flow ───────────────────────────────────────────────────

func runFullInstallFlow() {
	var soarType string
	var advancedMode bool
	var useVirusTotal bool
	var vtAPIKey string
	var confirmInstall bool

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("SOAR Engine").
				Description("Select your primary Security Orchestration platform.").
				Options(
					huh.NewOption("n8n (Lightweight, Highly Recommended)", "n8n"),
					huh.NewOption("Shuffle (Full Enterprise SOAR)", "Shuffle"),
				).
				Value(&soarType),

			huh.NewConfirm().
				Title("Enable Advanced Config?").
				Description("YES: Provide custom configurations manually (port mappings, memory alloc).\nNO: Automatically deploy with default configurations (Recommended).").
				Value(&advancedMode),
		),
		huh.NewGroup(
			huh.NewConfirm().
				Title("Integrate VirusTotal?").
				Description("YES: You'll be prompted for a VirusTotal API key for Wazuh threat scanning.\nNO: Skip VirusTotal integration.").
				Value(&useVirusTotal),
		),
		huh.NewGroup(
			huh.NewInput().
				Title("VirusTotal API Key").
				Description("1. Create account at virustotal.com\n2. Go to Profile → API Key\n3. Paste the 64-character key below:").
				EchoMode(huh.EchoModePassword).
				Value(&vtAPIKey).
				Validate(func(str string) error {
					if len(str) < 32 {
						return fmt.Errorf("API key is too short. Please paste a valid VirusTotal key")
					}
					return nil
				}),
		).WithHideFunc(func() bool { return !useVirusTotal }),
		huh.NewGroup(
			huh.NewConfirm().
				Title("Ready to Deploy Full Stack?").
				Description("YES: Start the installation of Wazuh SIEM + " + soarType + " SOAR + IRIS DFIR + MISP.\nNO: Cancel and return to menu.").
				Affirmative("Yes, start deployment!").
				Negative("No, cancel").
				Value(&confirmInstall),
		),
	).WithTheme(huh.ThemeDracula())

	if !runForm(form, banner) {
		abortToMenu()
		return
	}
	if !confirmInstall {
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#ef4444")).Render("\n[✖] Installation cancelled. Returning to main menu..."))
		main()
		return
	}

	// Detect network type (default to Private Network for full install)
	networkType := "Private Network"

	printSummaryBox("Full Installation Configuration", []string{
		lipgloss.NewStyle().Foreground(textMuted).Render("SOAR Engine  : ") +
			lipgloss.NewStyle().Foreground(successColor).Render(soarType),
		lipgloss.NewStyle().Foreground(textMuted).Render("IRIS DFIR    : ") +
			lipgloss.NewStyle().Foreground(successColor).Render("Enabled"),
		lipgloss.NewStyle().Foreground(textMuted).Render("MISP         : ") +
			lipgloss.NewStyle().Foreground(successColor).Render("Enabled"),
		lipgloss.NewStyle().Foreground(textMuted).Render("Setup Mode   : ") +
			lipgloss.NewStyle().Foreground(successColor).Render(func() string {
				if advancedMode {
					return "Advanced"
				}
				return "Standard"
			}()),
	})

	cfg := orchestration.Config{
		NetworkType:   networkType,
		SOAREngine:    soarType,
		AdvancedMode:  advancedMode,
		UseVirusTotal: useVirusTotal,
		VTAPIKey:      vtAPIKey,
	}

	fmt.Println()
	if err := orchestration.RunFullInstall(cfg); err != nil {
		log.Fatalf("\n[ERROR] Full installation failed: %v", err)
	}

	fmt.Println(strings.Repeat("─", 50))
	fmt.Println(lipgloss.NewStyle().Foreground(successColor).Bold(true).Render("✔ T-Guard Full Stack is up and running!"))
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#fbbf24")).Bold(true).Render("⚠️  ACTION REQUIRED: API CONFIGURATION"))
	fmt.Println(lipgloss.NewStyle().Foreground(textMuted).Render("Your SOC is running, but you MUST manually configure API keys for IRIS and MISP."))
	fmt.Println(lipgloss.NewStyle().Foreground(textMuted).Render("Please generate the keys from their respective dashboards, then select option [2] below."))
	fmt.Println()

	var nextStep string
	nextForm := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("What would you like to do next?").
				Options(
					huh.NewOption("[2] Proceed to Integrate Manual (Configure APIs)", "integrate"),
					huh.NewOption("[4] Proceed to Inject n8n Workflows", "inject"),
					huh.NewOption("Return to Main Menu", "menu"),
					huh.NewOption("Exit Installer", "exit"),
				).
				Value(&nextStep),
		),
	).WithTheme(huh.ThemeDracula())

	if err := nextForm.Run(); err != nil {
		os.Exit(0)
	}

	switch nextStep {
	case "integrate":
		runIntegrateFlow()
	case "inject":
		runInjectFlow()
	case "menu":
		main()
	case "exit":
		os.Exit(0)
	}
}

// ── Integrate Manual Flow ────────────────────────────────────────────────────

func runIntegrateFlow() {
	var (
		irisURL       string
		irisAPIKey    string
		mispURL       string
		mispAPIKey    string
		n8nURL        string
		vtAPIKey      string
		confirmSave   bool
	)

	// Load existing configuration if available
	var existingCfg orchestration.IntegrationConfig
	if data, err := os.ReadFile("/var/lib/tguard_state/integration.json"); err == nil {
		json.Unmarshal(data, &existingCfg)
		irisURL = existingCfg.IRISURL
		irisAPIKey = existingCfg.IRISAPIKey
		mispURL = existingCfg.MISPURL
		mispAPIKey = existingCfg.MISPAPIKey
		n8nURL = existingCfg.N8nURL
		vtAPIKey = existingCfg.VTAPIKey
	}

	getHint := func(key string) string {
		if len(key) > 5 {
			return fmt.Sprintf("\n(Currently configured: %s...)", key[:5])
		}
		return ""
	}

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("IRIS URL").
				Description("e.g. https://192.168.1.1:8443").
				Placeholder("https://").
				Value(&irisURL).
				Validate(func(s string) error {
					if strings.TrimSpace(s) == "" {
						return fmt.Errorf("IRIS URL is required")
					}
					return nil
				}),

			huh.NewInput().
				Title("IRIS API Key").
				Description("Profile > My Settings > API Key" + getHint(irisAPIKey)).
				EchoMode(huh.EchoModePassword).
				Value(&irisAPIKey).
				Validate(func(s string) error {
					if strings.TrimSpace(s) == "" {
						return fmt.Errorf("IRIS API key is required")
					}
					return nil
				}),
		),
		huh.NewGroup(
			huh.NewInput().
				Title("MISP URL").
				Description("e.g. https://192.168.1.1:1443").
				Placeholder("https://").
				Value(&mispURL).
				Validate(func(s string) error {
					if strings.TrimSpace(s) == "" {
						return fmt.Errorf("MISP URL is required")
					}
					return nil
				}),

			huh.NewInput().
				Title("MISP API Key").
				Description("Administration > List Auth Keys" + getHint(mispAPIKey)).
				EchoMode(huh.EchoModePassword).
				Value(&mispAPIKey).
				Validate(func(s string) error {
					if strings.TrimSpace(s) == "" {
						return fmt.Errorf("MISP API key is required")
					}
					return nil
				}),
		),
		huh.NewGroup(
			huh.NewInput().
				Title("n8n URL (Optional)").
				Description("Leave blank to skip n8n webhook integration.").
				Placeholder("http://").
				Value(&n8nURL),

			huh.NewInput().
				Title("VirusTotal API Key (Optional)").
				Description("If you skipped VT during Full Install, you can add it here." + getHint(vtAPIKey)).
				EchoMode(huh.EchoModePassword).
				Value(&vtAPIKey),
		),
		huh.NewGroup(
			huh.NewConfirm().
				Title("Save and Apply Integration?").
				Description("YES: Credentials will be securely stored and applied to connect all services to your SOAR engine.\nNO: Cancel integration process.").
				Affirmative("Yes, save and apply").
				Negative("No, cancel").
				Value(&confirmSave),
		),
	).WithTheme(huh.ThemeDracula())

	if !runForm(form, banner) {
		abortToMenu()
		return
	}
	if !confirmSave {
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#ef4444")).Render("\n[✖] Integration cancelled. Returning to main menu..."))
		main()
		return
	}

	intCfg := orchestration.IntegrationConfig{
		IRISURL:       irisURL,
		IRISAPIKey:    irisAPIKey,
		MISPURL:       mispURL,
		MISPAPIKey:    mispAPIKey,
		N8nURL:        n8nURL,
		VTAPIKey:      vtAPIKey,
	}

	fmt.Println()
	if err := orchestration.RunIntegration(intCfg); err != nil {
		log.Fatalf("\n[ERROR] Integration failed: %v", err)
	}

	var nextStep string
	nextForm := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("What would you like to do next?").
				Options(
					huh.NewOption("[4] Proceed to Inject n8n Workflows", "inject"),
					huh.NewOption("Return to Main Menu", "menu"),
					huh.NewOption("Exit Installer", "exit"),
				).
				Value(&nextStep),
		),
	).WithTheme(huh.ThemeDracula())

	if err := nextForm.Run(); err != nil {
		os.Exit(0)
	}

	switch nextStep {
	case "inject":
		runInjectFlow()
	case "menu":
		main()
	case "exit":
		os.Exit(0)
	}
}

// ── PoC Flow ─────────────────────────────────────────────────────────────────

func runPoCFlow() {
	var selectedScenarios []string
	var targetIP string
	var confirmRun bool

	// Explicitly target the local host agent (127.0.0.1) to guarantee PoC hits the Agent
	detectedIP := "127.0.0.1"

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewMultiSelect[string]().
				Title("Select PoC Scenarios").
				Description("Choose which security scenarios to simulate (at least 1 required).").
				Options(
					huh.NewOption("SSH Brute Force", "bruteforce"),
					huh.NewOption("EICAR Malware Test File", "malware"),
					huh.NewOption("Web Defacement", "webdeface"),
				).
				Value(&selectedScenarios).
				Validate(func(v []string) error {
					if len(v) == 0 {
						return fmt.Errorf("select at least one scenario")
					}
					return nil
				}),

			huh.NewInput().
				Title("Target IP").
				Description("IP address for SSH brute force scenario (leave blank to auto-detect).").
				Placeholder(detectedIP).
				Value(&targetIP),
		),
		huh.NewGroup(
			huh.NewConfirm().
				Title("Run Proof of Concept (PoC)?").
				Description("YES: Execute simulated attack scenarios on the target IP. (Ensure you have authorization!)\nNO: Cancel PoC execution.").
				Affirmative("Yes, run PoC!").
				Negative("No, cancel").
				Value(&confirmRun),
		),
	).WithTheme(huh.ThemeDracula())

	if !runForm(form, banner) {
		abortMsg()
	}
	if !confirmRun {
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#ef4444")).Render("\n[✖] PoC execution cancelled. Returning to main menu..."))
		main()
		return
	}

	// Use detected IP if user left it blank
	if strings.TrimSpace(targetIP) == "" {
		targetIP = detectedIP
	}

	fmt.Println()
	if err := orchestration.RunPoC(selectedScenarios, targetIP); err != nil {
		log.Fatalf("\n[ERROR] PoC run failed: %v", err)
	}

	fmt.Println(strings.Repeat("─", 50))
	fmt.Println(lipgloss.NewStyle().Foreground(successColor).Bold(true).Render("✔ PoC scenarios completed. Check Wazuh alerts!"))
	fmt.Println()

	var nextStep string
	nextForm := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("What would you like to do next?").
				Options(
					huh.NewOption("Return to Main Menu", "menu"),
					huh.NewOption("Exit Installer", "exit"),
				).
				Value(&nextStep),
		),
	).WithTheme(huh.ThemeDracula())

	if err := nextForm.Run(); err != nil {
		os.Exit(0)
	}

	switch nextStep {
	case "menu":
		main()
	case "exit":
		os.Exit(0)
	}
}

// ── Uninstall Flow ───────────────────────────────────────────────────────────

func runUninstallFlow() {
	var confirmUninstall bool

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().
				Title("⚠️ Uninstall T-Guard?").
				Description("YES: Forcefully stop and permanently remove ALL T-Guard containers, volumes, certificates, and state files. (DATA WILL BE LOST!)\nNO: Cancel and keep T-Guard installed.").
				Affirmative("Yes, uninstall everything (Irreversible!)").
				Negative("No, keep T-Guard").
				Value(&confirmUninstall),
		),
	).WithTheme(huh.ThemeDracula())

	if !runForm(form, banner) {
		abortMsg()
	}
	if !confirmUninstall {
		fmt.Println(lipgloss.NewStyle().Foreground(successColor).Render("\n[✔] Uninstall cancelled. Returning to main menu..."))
		main()
		return
	}

	paths, err := env.InitPaths()
	if err != nil {
		log.Fatalf("[ERROR] Failed to resolve paths: %v", err)
	}

	fmt.Println()
	if err := orchestration.RunUninstall(paths); err != nil {
		log.Fatalf("\n[ERROR] Uninstall failed: %v", err)
	}

	var nextStep string
	nextForm := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("What would you like to do next?").
				Options(
					huh.NewOption("Return to Main Menu", "menu"),
					huh.NewOption("Exit Installer", "exit"),
				).
				Value(&nextStep),
		),
	).WithTheme(huh.ThemeDracula())

	if err := nextForm.Run(); err != nil {
		os.Exit(0)
	}

	switch nextStep {
	case "menu":
		main()
	case "exit":
		os.Exit(0)
	}
}

// ── Inject Workflows Flow ───────────────────────────────────────────────────

func runInjectFlow() {
	var confirmInject bool

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().
				Title("Inject n8n SOC Workflows?").
				Description("YES: Automatically load advanced SOC playbooks (Master Triage, Anti-Duplicate, MISP Malware Response) into your n8n instance.\nNO: Cancel workflow injection.").
				Affirmative("Yes, inject workflows").
				Negative("No, cancel").
				Value(&confirmInject),
		),
	).WithTheme(huh.ThemeDracula())

	if !runForm(form, banner) {
		abortMsg()
	}
	if !confirmInject {
		fmt.Println(lipgloss.NewStyle().Foreground(successColor).Render("\n[✔] Injection cancelled. Returning to main menu..."))
		main()
		return
	}

	paths, err := env.InitPaths()
	if err != nil {
		log.Fatalf("[ERROR] Failed to resolve paths: %v", err)
	}

	fmt.Println()
	if err := orchestration.RunInject(paths); err != nil {
		log.Fatalf("\n[ERROR] Workflow injection failed: %v", err)
	}

	var nextStep string
	nextForm := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("What would you like to do next?").
				Options(
					huh.NewOption("Return to Main Menu", "menu"),
					huh.NewOption("Exit Installer", "exit"),
				).
				Value(&nextStep),
		),
	).WithTheme(huh.ThemeDracula())

	if err := nextForm.Run(); err != nil {
		os.Exit(0)
	}

	switch nextStep {
	case "menu":
		main()
	case "exit":
		os.Exit(0)
	}
}

// ── View Credentials Flow ────────────────────────────────────────────────────

func runViewCredentialsFlow() {
	paths, err := env.InitPaths()
	if err != nil {
		log.Fatalf("[ERROR] Failed to resolve paths: %v", err)
	}

	hostIP := os.Getenv("TGUARD_HOST_IP")
	if hostIP == "" {
		hostIP, err = network.DetectPrivateIP()
		if err != nil || hostIP == "" {
			hostIP, _ = network.DetectPublicIP()
		}
	}

	wazuhDir := filepath.Join(paths.RootDir, "wazuh-docker", "single-node")

	// Fallback/dummy config if state not fully loaded
	cfg := orchestration.Config{
		SOAREngine:    "n8n", 
		UseVirusTotal: false, 
	}

	orchestration.PrintSummary(cfg, hostIP, wazuhDir)

	var nextStep string
	nextForm := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("").
				Options(
					huh.NewOption("Return to Main Menu", "menu"),
					huh.NewOption("Exit", "exit"),
				).
				Value(&nextStep),
		),
	).WithTheme(huh.ThemeDracula())

	if err := nextForm.Run(); err != nil {
		os.Exit(0)
	}

	if nextStep == "menu" {
		main()
	} else {
		os.Exit(0)
	}
}
