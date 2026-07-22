package orchestration

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"tguard-installer/pkg/env"
)

// RunPoC runs the T-Guard Proof of Concept scenarios by invoking the Python script.
// scenarios: slice containing one or more of "bruteforce", "malware", "webdeface".
// targetIP:  the target IP for SSH brute force; empty string auto-detects.
func RunPoC(scenarios []string, targetIP string) error {
	cyanStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#00e5ff")).Bold(true)
	dimStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#6b7280"))
	greenStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#10b981")).Bold(true)

	if len(scenarios) == 0 {
		return fmt.Errorf("no scenarios selected — select at least one PoC scenario")
	}

	paths, _ := env.InitPaths()
	pocScript := filepath.Join(paths.RootDir, "scripts", "tguard_poc.py")

	// Verify the PoC script exists
	if _, err := os.Stat(pocScript); err != nil {
		return fmt.Errorf("PoC script not found at %s: %v", pocScript, err)
	}

	allScenarios := map[string]bool{"bruteforce": true, "malware": true, "webdeface": true}
	selectedSet := make(map[string]bool, len(scenarios))
	for _, s := range scenarios {
		selectedSet[s] = true
	}

	allSelected := len(selectedSet) == len(allScenarios)
	for k := range allScenarios {
		if !selectedSet[k] {
			allSelected = false
			break
		}
	}

	var steps []*Step
	if allSelected {
		steps = append(steps, buildPocStep("all", targetIP, pocScript))
	} else {
		for _, scenario := range scenarios {
			steps = append(steps, buildPocStep(scenario, targetIP, pocScript))
		}
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

	var sb strings.Builder
	sb.WriteString(greenStyle.Render("  [✔] All requested PoC scenarios completed successfully!") + "\n\n")
	for _, step := range steps {
		if step.Logs != "" {
			sb.WriteString(cyanStyle.Render(fmt.Sprintf("  --- Output for %s ---", step.Title)) + "\n")
			lines := strings.Split(step.Logs, "\n")
			for _, line := range lines {
				if strings.TrimSpace(line) != "" {
					sb.WriteString("    " + dimStyle.Render(line) + "\n")
				}
			}
			sb.WriteString("\n")
		}
	}

	content := sb.String()
	if uiModel.Width > 0 {
		fmt.Print(lipgloss.PlaceHorizontal(uiModel.Width, lipgloss.Center, content))
	} else {
		fmt.Println(content)
	}
	fmt.Println()

	return nil
}

func buildPocStep(scenario, targetIP string, pocScript string) *Step {
	return &Step{
		Key:   "poc_" + scenario,
		Title: "Running PoC Scenario: " + scenario,
		Action: func() (bool, string, error) {
			args := []string{pocScript, "--scenario", scenario}
			if targetIP != "" {
				args = append(args, "--target-ip", targetIP)
			}
			cmd := exec.Command("python3", args...)
			out, err := cmd.CombinedOutput()
			if err != nil {
				return false, string(out), fmt.Errorf("PoC scenario '%s' failed: %v", scenario, err)
			}
			return false, string(out), nil
		},
	}
}
