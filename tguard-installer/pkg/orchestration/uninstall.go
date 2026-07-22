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

// RunUninstall performs a complete clean removal of all T-Guard components.
// It runs docker compose down -v in each service directory, removes state, and
// removes generated certificate files.
func RunUninstall(paths *env.InstallerPaths) error {
	redStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#ef4444")).Bold(true)
	dimStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#6b7280"))



	serviceDirs := []struct {
		key  string
		rel  string
		name string
	}{
		{"wazuh", filepath.Join("wazuh-docker", "single-node"), "Wazuh SIEM"},
		{"n8n", "n8n", "n8n SOAR"},
		{"iris", "iris-web", "IRIS DFIR"},
		{"misp", "misp-docker", "MISP Threat Intel"},
		{"shuffle", "shuffle", "Shuffle SOAR"},
	}

	var steps []*Step

	for _, svc := range serviceDirs {
		svc := svc // capture loop variable
		steps = append(steps, &Step{
			Key:   "uninstall_" + svc.key,
			Title: "Stopping & Removing " + svc.name,
			Action: func() (bool, string, error) {
				dir := filepath.Join(paths.RootDir, svc.rel)
				if _, err := os.Stat(dir); os.IsNotExist(err) {
					return false, fmt.Sprintf("%s directory not found, skipping", svc.name), nil
				}
				
				// Ensure docker-compose.yml exists before attempting to run compose down
				composeFile := filepath.Join(dir, "docker-compose.yml")
				if _, err := os.Stat(composeFile); os.IsNotExist(err) {
					return false, fmt.Sprintf("%s has no docker-compose.yml, skipping", svc.name), nil
				}

				if out, err := composeDown(dir); err != nil {
					return false, out, fmt.Errorf("%s removal had errors: %v", svc.name, err)
				}
				return false, fmt.Sprintf("%s removed", svc.name), nil
			},
		})
	}

	steps = append(steps, &Step{
		Key:   "uninstall_certs_state",
		Title: "Removing state files and certs",
		Action: func() (bool, string, error) {
			wazuhDir := filepath.Join(paths.RootDir, "wazuh-docker", "single-node")
			certDir := filepath.Join(wazuhDir, "config", "wazuh_indexer_ssl_certs")
			
			var msgs []string
			if out, err := runSudoRM(certDir); err != nil {
				msgs = append(msgs, fmt.Sprintf("Certificate removal failed: %v (%s)", err, out))
			} else {
				msgs = append(msgs, "Certificates removed.")
			}

			stateDir := "/var/lib/tguard_state"
			if out, err := runSudoRM(stateDir); err != nil {
				msgs = append(msgs, fmt.Sprintf("State dir removal failed: %v (%s)", err, out))
			} else {
				msgs = append(msgs, "State directory removed.")
			}

			return false, strings.Join(msgs, "\n"), nil
		},
	})

	steps = append(steps, &Step{
		Key:   "uninstall_system",
		Title: "Pruning Docker and cleaning system traces",
		Action: func() (bool, string, error) {
			var msgs []string
			
			// Docker prune
			exec.Command("sudo", "docker", "container", "prune", "-f").Run()
			exec.Command("sudo", "docker", "volume", "prune", "-f").Run()
			exec.Command("sudo", "docker", "network", "prune", "-f").Run()
			msgs = append(msgs, "Docker system pruned.")

			// Remove Wazuh Agent (if installed)
			exec.Command("sudo", "apt-get", "remove", "--purge", "wazuh-agent", "-y").Run()
			exec.Command("sudo", "rm", "-rf", "/var/ossec").Run()
			msgs = append(msgs, "Wazuh Agent removed.")

			return false, strings.Join(msgs, "\n"), nil
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

	content := redStyle.Render("  [✔] T-Guard has been completely uninstalled.") + "\n" +
		dimStyle.Render("  [ℹ] Docker images remain on disk. Run 'docker image prune -a' to free space.")

	if uiModel.Width > 0 {
		fmt.Print(lipgloss.PlaceHorizontal(uiModel.Width, lipgloss.Center, content))
	} else {
		fmt.Println(content)
	}
	fmt.Println()

	return nil
}

// composeDown runs docker compose down -v in the given directory.
func composeDown(dir string) (string, error) {
	cmd := exec.Command("sudo", "docker", "compose", "down", "-v")
	cmd.Dir = dir

	out, err := cmd.CombinedOutput()
	if err != nil {
		cmdV1 := exec.Command("sudo", "docker-compose", "down", "-v")
		cmdV1.Dir = dir
		outV1, errV1 := cmdV1.CombinedOutput()
		if errV1 != nil {
			return string(out) + "\n" + string(outV1), errV1
		}
		return string(outV1), nil
	}
	return string(out), nil
}

// runSudoRM removes a path using sudo rm -rf.
func runSudoRM(path string) (string, error) {
	cmd := exec.Command("sudo", "rm", "-rf", path)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
