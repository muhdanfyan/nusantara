package orchestration

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"tguard-installer/pkg/env"
)

// RunInject loads n8n workflows from the workflows directory into the running n8n container.
func RunInject(paths *env.InstallerPaths) error {
	greenStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#10b981")).Bold(true)
	dimStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#6b7280"))

	steps := []*Step{
		{
			Key:   "check_n8n",
			Title: "Checking if n8n is running",
			Action: func() (bool, string, error) {
				cmd := exec.Command("sudo", "docker", "inspect", "-f", "{{.State.Running}}", "tguard-n8n")
				out, err := cmd.CombinedOutput()
				if err != nil || !strings.Contains(string(out), "true") {
					return false, string(out), fmt.Errorf("tguard-n8n container is not running. Please run Full Installation first")
				}
				return false, "n8n is running", nil
			},
		},
		{
			Key:   "inject_workflows",
			Title: "Injecting Advanced SOC Workflows",
			Action: func() (bool, string, error) {
				workflowsDir := filepath.Join(paths.RootDir, "n8n", "workflows")
				
				// Ensure directory exists in container
				cmdMkdir := exec.Command("sudo", "docker", "exec", "-u", "node", "tguard-n8n", "mkdir", "-p", "/tmp/workflows")
				if out, err := cmdMkdir.CombinedOutput(); err != nil {
					return false, string(out), fmt.Errorf("failed to create temp dir in container: %v", err)
				}

				// Copy files to container
				cmdCp := exec.Command("sudo", "docker", "cp", workflowsDir+"/.", "tguard-n8n:/tmp/workflows/")
				if out, err := cmdCp.CombinedOutput(); err != nil {
					return false, string(out), fmt.Errorf("failed to copy workflows to container: %v", err)
				}

				// Import workflows
				cmdImport := exec.Command("sudo", "docker", "exec", "-u", "node", "tguard-n8n", "n8n", "import:workflow", "--separate", "--input=/tmp/workflows")
				out, err := cmdImport.CombinedOutput()
				if err != nil {
					return false, string(out), fmt.Errorf("failed to import workflows via n8n CLI: %v", err)
				}

				return false, string(out), nil
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

	content := greenStyle.Render("  [✔] Advanced SOC Workflows injected successfully!") + "\n" +
		dimStyle.Render("  [ℹ] Log in to your n8n dashboard to view and activate them.")

	if uiModel.Width > 0 {
		fmt.Print(lipgloss.PlaceHorizontal(uiModel.Width, lipgloss.Center, content))
	} else {
		fmt.Println(content)
	}
	fmt.Println()

	return nil
}
