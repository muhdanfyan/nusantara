package orchestration

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"tguard-installer/pkg/state"
)

type StepStatus int

const (
	StatusPending StepStatus = iota
	StatusRunning
	StatusDone
	StatusSkipped
	StatusError
)

type Step struct {
	Key    string
	Title  string
	Action func() (bool, string, error) // (skipped, logs, error)
	Status StepStatus
	Err    error
	Logs   string
}

type InstallUI struct {
	Steps        []*Step
	CurrentStep  int
	Spinner      spinner.Model
	Done         bool
	Err          error
	ErrorPaused  bool // true = error terjadi, menunggu keypress user
	Width        int
	Height       int
}

type stepCompleteMsg struct {
	err     error
	logs    string
	skipped bool
}

func initialModel(steps []*Step) InstallUI {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = cyan

	return InstallUI{
		Steps:   steps,
		Spinner: s,
	}
}

func (m InstallUI) Init() tea.Cmd {
	return tea.Batch(m.Spinner.Tick, m.runCurrentStep())
}

func (m InstallUI) runCurrentStep() tea.Cmd {
	if m.CurrentStep >= len(m.Steps) {
		return nil
	}

	step := m.Steps[m.CurrentStep]
	step.Status = StatusRunning

	return func() (msg tea.Msg) {
		// ── Panic recovery ────────────────────────────────────────────────────
		// Mencegah panic di dalam action menyebabkan TUI hang tanpa pesan.
		defer func() {
			if r := recover(); r != nil {
				msg = stepCompleteMsg{
					err: fmt.Errorf("unexpected panic in step %q: %v\n\nThis is likely a bug. Please report it.", step.Key, r),
				}
			}
		}()

		skipped, logs, err := step.Action()
		return stepCompleteMsg{err: err, logs: logs, skipped: skipped}
	}
}

func (m InstallUI) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.Width = msg.Width
		m.Height = msg.Height

	case tea.KeyMsg:
		// Jika sedang dalam mode error-pause, APAPUN key yang ditekan akan keluar
		if m.ErrorPaused {
			return m, tea.Quit
		}
		if msg.String() == "ctrl+c" || msg.String() == "q" {
			m.Err = fmt.Errorf("installation aborted by user (Ctrl+C)")
			m.ErrorPaused = true
			return m, nil
		}

	case stepCompleteMsg:
		step := m.Steps[m.CurrentStep]
		step.Logs = msg.logs

		if msg.err != nil {
			step.Status = StatusError
			step.Err = msg.err
			m.Err = msg.err
			m.Done = true
			// TIDAK langsung quit — masuk mode pause agar user bisa baca error
			m.ErrorPaused = true
			return m, nil
		}

		if msg.skipped {
			step.Status = StatusSkipped
		} else if step.Status == StatusRunning {
			step.Status = StatusDone
			state.MarkStepDone(step.Key)
		}

		m.CurrentStep++
		if m.CurrentStep >= len(m.Steps) {
			m.Done = true
			return m, tea.Quit
		}
		return m, m.runCurrentStep()

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.Spinner, cmd = m.Spinner.Update(msg)
		return m, cmd
	}
	return m, nil
}

// diagnoseError mencoba mengidentifikasi penyebab umum dari pesan error
// dan memberikan saran spesifik kepada user.
func diagnoseError(stepKey string, err error) []string {
	if err == nil {
		return nil
	}
	errStr := strings.ToLower(err.Error())
	var hints []string

	// ── MISP-related diagnostics ──────────────────────────────────────────────
	if strings.Contains(stepKey, "misp") || strings.Contains(errStr, "misp") {
		if strings.Contains(errStr, "unhealthy") || strings.Contains(errStr, "health") {
			hints = append(hints,
				"MISP takes 3–10 minutes to fully initialize on first boot.",
				"Common causes of MISP unhealthy:",
				"  • MariaDB is still running InnoDB recovery (wait 5 min & retry)",
				"  • misp-modules has not finished loading Python packages",
				"  • BASE_URL in misp-docker/.env does not match your server IP",
				"Fix: Run 'docker logs misp-docker-misp-core-1 --tail 50' to inspect.",
			)
		}
		if strings.Contains(errStr, "database") || strings.Contains(errStr, "mysql") || strings.Contains(errStr, "mariadb") {
			hints = append(hints,
				"Database issue detected.",
				"  • Check if MariaDB container is healthy: 'docker ps | grep misp'",
				"  • Try: 'docker compose -f misp-docker/docker-compose.yml restart db'",
			)
		}
		if strings.Contains(errStr, "compose") || strings.Contains(errStr, "pull") {
			hints = append(hints,
				"Docker image pull issue.",
				"  • MISP images are large (2–4 GB). Slow network may cause timeout.",
				"  • Retry by running the installer again (steps already done are skipped).",
				"  • If on IPv6-only network, disable IPv6 in Docker: /etc/docker/daemon.json",
			)
		}
	}

	// ── Docker / network ──────────────────────────────────────────────────────
	if strings.Contains(errStr, "network is unreachable") || strings.Contains(errStr, "dial tcp") {
		hints = append(hints,
			"Network connectivity issue detected.",
			"  • IPv6 may be enabled but not working. Fix: add to /etc/docker/daemon.json:",
			`    { "ipv6": false, "ip6tables": false }`,
			"  • Then run: sudo systemctl restart docker",
			"  • Ensure the server has internet access: curl -I https://registry-1.docker.io",
		)
	}

	if strings.Contains(errStr, "timed out") || strings.Contains(errStr, "timeout") {
		hints = append(hints,
			"Operation timed out.",
			"  • Your network connection may be slow. The installer will skip completed",
			"    steps if you re-run it — you will not start from scratch.",
			"  • Try again when network is more stable.",
			"  • If pulling Docker images, check: docker pull <image-name> manually first.",
		)
	}

	if strings.Contains(errStr, "permission denied") || strings.Contains(errStr, "sudo") {
		hints = append(hints,
			"Permission denied.",
			"  • The installer must be run as root: sudo ./tguard-installer-cli",
		)
	}

	if strings.Contains(errStr, "no space left") || strings.Contains(errStr, "disk") {
		hints = append(hints,
			"Disk space issue.",
			"  • Check available space: df -h /",
			"  • T-Guard requires at least 20 GB free.",
			"  • Run: docker system prune -f  to reclaim space from old images.",
		)
	}

	if strings.Contains(errStr, "gpg") || strings.Contains(errStr, "key") {
		hints = append(hints,
			"GPG key import issue.",
			"  • This usually means the download was incomplete.",
			"  • Check internet access and retry. The installer will resume from this step.",
		)
	}

	// Generic fallback
	if len(hints) == 0 {
		hints = append(hints,
			"Unexpected error. Suggestions:",
			"  • Check Docker status: sudo systemctl status docker",
			"  • Check disk space: df -h /",
			"  • Check internet: curl -I https://registry-1.docker.io",
			"  • Re-run the installer — completed steps will be skipped automatically.",
		)
	}

	return hints
}

const banner = `
  ████████╗       ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
  ╚══██╔══╝      ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
     ██║   █████╗██║  ███╗██║   ██║███████║██████╔╝██║  ██║
     ██║   ╚════╝██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
     ██║         ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
     ╚═╝          ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 
`

func (m InstallUI) View() string {
	if m.Width == 0 {
		return ""
	}

	bannerStyle := lipgloss.NewStyle().
		Foreground(cyan.GetForeground()).
		Bold(true).
		Align(lipgloss.Center)

	taglineStyle := lipgloss.NewStyle().
		Foreground(muted.GetForeground()).
		Italic(true).
		Align(lipgloss.Center).
		MarginBottom(1)

	var stepsView strings.Builder
	for _, step := range m.Steps {
		var statusIcon string
		switch step.Status {
		case StatusPending:
			statusIcon = muted.Render("[ ]")
		case StatusRunning:
			statusIcon = m.Spinner.View()
		case StatusDone:
			statusIcon = green.Render("[✔]")
		case StatusSkipped:
			statusIcon = muted.Render("[⟳]")
		case StatusError:
			statusIcon = red.Render("[✖]")
		}

		title := step.Title
		switch step.Status {
		case StatusRunning:
			title = cyan.Render(title)
		case StatusSkipped:
			title = muted.Render(title + " (already done — skipped)")
		case StatusDone:
			title = bold.Render(title)
		case StatusError:
			title = red.Render(title)
		}

		stepsView.WriteString(fmt.Sprintf("%s %s\n", statusIcon, title))

		// Tampilkan log step
		if step.Logs != "" && step.Status != StatusPending && step.Status != StatusRunning {
			for _, line := range strings.Split(step.Logs, "\n") {
				if strings.TrimSpace(line) != "" {
					stepsView.WriteString(fmt.Sprintf("    %s\n", muted.Render("→ "+line)))
				}
			}
		}

		// Tampilkan detail error step
		if step.Status == StatusError && step.Err != nil {
			stepsView.WriteString("\n")
			errLines := strings.Split(step.Err.Error(), "\n")
			maxLines := 8
			if len(errLines) > maxLines {
				for i := 0; i < maxLines; i++ {
					stepsView.WriteString(fmt.Sprintf("    %s %s\n", red.Render("→"), errLines[i]))
				}
				stepsView.WriteString(fmt.Sprintf("    %s\n", red.Render("→ ... (truncated — re-run with logs for full output)")))
			} else {
				for _, line := range errLines {
					stepsView.WriteString(fmt.Sprintf("    %s %s\n", red.Render("→"), line))
				}
			}

			// Tampilkan diagnosis & hints
			hints := diagnoseError(step.Key, step.Err)
			if len(hints) > 0 {
				stepsView.WriteString("\n")
				stepsView.WriteString(fmt.Sprintf("    %s\n", amber.Render("── Diagnosis & Recommended Actions ──")))
				for _, h := range hints {
					stepsView.WriteString(fmt.Sprintf("    %s\n", amber.Render(h)))
				}
			}
		}
	}

	// Pesan khusus saat error-pause
	if m.ErrorPaused {
		stepsView.WriteString("\n")
		stepsView.WriteString(red.Render("  ✖ Installation stopped due to the error above.\n"))
		stepsView.WriteString(muted.Render("  Re-running the installer is safe — completed steps will be skipped.\n"))
		stepsView.WriteString("\n")
		stepsView.WriteString(bold.Render("  Press any key to exit.\n"))
	}

	boxStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(cyan.GetForeground()).
		Padding(1, 4)

	bannerStr := bannerStyle.Render(banner)
	taglineStr := taglineStyle.Render("NEXT-GENERATION SECURITY OPERATIONS CENTER • v2.2")
	stepsStr := boxStyle.Render(stepsView.String())

	content := lipgloss.JoinVertical(lipgloss.Center, bannerStr, taglineStr, stepsStr)
	return lipgloss.Place(m.Width, m.Height, lipgloss.Center, lipgloss.Center, content)
}
