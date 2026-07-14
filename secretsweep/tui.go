package main

import (
	"bufio"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type phase int

const (
	phaseDiscover phase = iota
	phaseScan
	phaseReview
	phaseConfirm
	phaseRun
	phaseDone
)

var (
	styleTitle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("212"))
	styleSubtle   = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	styleDanger   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("196"))
	styleOK       = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("42"))
	styleWarn     = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	styleHelp     = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	styleViewport = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("241")).Padding(0, 1)
)

type reposMsg struct {
	repos []string
	err   error
}

type scannedMsg struct {
	index    int
	findings []Finding
	err      error
}

type engineEvMsg struct {
	line string
	done bool
	exit int
	err  error
}

type model struct {
	targets    []string
	enginePath string

	phase   phase
	spinner spinner.Model
	width   int
	height  int

	repos     []string
	scanIndex int
	findings  []Finding
	scanErrs  []string

	tbl           table.Model
	confirmInput  textinput.Model
	pendingAction EngineAction

	viewport    viewport.Model
	engineLines []string
	engineCh    chan engineEvMsg
	engineExit  int
	ranAction   EngineAction

	err error
}

func newModel(targets []string, enginePath string) model {
	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("212"))

	ti := textinput.New()
	ti.Placeholder = "rewrite"
	ti.CharLimit = 16
	ti.Width = 24

	vp := viewport.New(80, 16)

	return model{
		targets:      targets,
		enginePath:   enginePath,
		phase:        phaseDiscover,
		spinner:      sp,
		confirmInput: ti,
		viewport:     vp,
		engineExit:   -1,
	}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, discoverCmd(m.targets))
}

func discoverCmd(targets []string) tea.Cmd {
	return func() tea.Msg {
		repos, err := DiscoverRepos(targets)
		return reposMsg{repos: repos, err: err}
	}
}

func scanCmd(repo string, index int) tea.Cmd {
	return func() tea.Msg {
		findings, err := ScanRepo(repo)
		return scannedMsg{index: index, findings: findings, err: err}
	}
}

func (m *model) startEngine(action EngineAction) tea.Cmd {
	secrets, _ := UniqueSecrets(m.findings)
	cmd, cleanup, err := BuildEngineCmd(m.enginePath, action, secrets, m.repos)
	if err != nil {
		m.err = err
		m.phase = phaseDone
		return nil
	}
	ch := make(chan engineEvMsg, 64)
	m.engineCh = ch
	m.engineLines = nil
	m.ranAction = action
	m.phase = phaseRun

	pr, pw := io.Pipe()
	cmd.Stdout = pw
	cmd.Stderr = pw
	if err := cmd.Start(); err != nil {
		cleanup()
		m.err = err
		m.phase = phaseDone
		return nil
	}
	exitCh := make(chan int, 1)
	go func() {
		err := cmd.Wait()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			code = -1
		}
		pw.Close()
		exitCh <- code
	}()
	go func() {
		defer cleanup()
		scanner := bufio.NewScanner(pr)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scanner.Scan() {
			ch <- engineEvMsg{line: scanner.Text()}
		}
		ch <- engineEvMsg{done: true, exit: <-exitCh}
		close(ch)
	}()
	return listenEngine(ch)
}

func listenEngine(ch chan engineEvMsg) tea.Cmd {
	return func() tea.Msg {
		ev, ok := <-ch
		if !ok {
			return nil
		}
		return ev
	}
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.viewport.Width = max(40, msg.Width-4)
		m.viewport.Height = max(8, msg.Height-8)
		if len(m.repos) > 0 || m.phase >= phaseReview {
			m.rebuildTable()
		}
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case reposMsg:
		if msg.err != nil {
			m.err = msg.err
			m.phase = phaseDone
			return m, nil
		}
		m.repos = msg.repos
		if len(m.repos) == 0 {
			m.phase = phaseDone
			return m, nil
		}
		if !TrivyAvailable() {
			m.err = fmt.Errorf("trivy is not installed; install it with: brew install trivy")
			m.phase = phaseDone
			return m, nil
		}
		m.phase = phaseScan
		m.scanIndex = 0
		return m, scanCmd(m.repos[0], 0)

	case scannedMsg:
		if msg.err != nil {
			m.scanErrs = append(m.scanErrs, fmt.Sprintf("%s: %v", m.repos[msg.index], msg.err))
		}
		m.findings = append(m.findings, msg.findings...)
		if msg.index+1 < len(m.repos) {
			m.scanIndex = msg.index + 1
			return m, scanCmd(m.repos[m.scanIndex], m.scanIndex)
		}
		m.phase = phaseReview
		m.rebuildTable()
		return m, nil

	case engineEvMsg:
		if msg.done {
			m.engineExit = msg.exit
			m.phase = phaseDone
			return m, nil
		}
		m.engineLines = append(m.engineLines, msg.line)
		m.viewport.SetContent(strings.Join(m.engineLines, "\n"))
		m.viewport.GotoBottom()
		return m, listenEngine(m.engineCh)
	}
	return m, nil
}

func (m model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch m.phase {
	case phaseConfirm:
		switch msg.String() {
		case "esc":
			m.phase = phaseReview
			m.confirmInput.Reset()
			return m, nil
		case "enter":
			if m.confirmInput.Value() == "rewrite" {
				m.confirmInput.Reset()
				return m, tea.Batch(m.spinner.Tick, m.startEngine(ActionRewrite))
			}
			m.confirmInput.Reset()
			return m, nil
		case "ctrl+c":
			return m, tea.Quit
		}
		var cmd tea.Cmd
		m.confirmInput, cmd = m.confirmInput.Update(msg)
		return m, cmd

	case phaseReview:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			return m, tea.Quit
		case "s":
			return m, tea.Batch(m.spinner.Tick, m.startEngine(ActionScan))
		case "d":
			return m, tea.Batch(m.spinner.Tick, m.startEngine(ActionDryRun))
		case "r":
			secrets, _ := UniqueSecrets(m.findings)
			if len(secrets) == 0 {
				return m, nil
			}
			m.phase = phaseConfirm
			m.confirmInput.Focus()
			return m, textinput.Blink
		}
		var cmd tea.Cmd
		m.tbl, cmd = m.tbl.Update(msg)
		return m, cmd

	case phaseRun:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
		var cmd tea.Cmd
		m.viewport, cmd = m.viewport.Update(msg)
		return m, cmd

	case phaseDone:
		switch msg.String() {
		case "q", "ctrl+c", "esc", "enter":
			return m, tea.Quit
		case "b":
			if len(m.findings) > 0 {
				m.phase = phaseReview
				return m, nil
			}
		}
		var cmd tea.Cmd
		m.viewport, cmd = m.viewport.Update(msg)
		return m, cmd

	default: // discover, scan
		if msg.String() == "ctrl+c" || msg.String() == "q" {
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m *model) rebuildTable() {
	width := m.width
	if width == 0 {
		width = 100
	}
	fileWidth := max(24, width-78)
	columns := []table.Column{
		{Title: "Severity", Width: 8},
		{Title: "Rule", Width: 20},
		{Title: "Repository", Width: 22},
		{Title: "File:Line", Width: fileWidth},
		{Title: "Secret", Width: 20},
	}
	sorted := make([]Finding, len(m.findings))
	copy(sorted, m.findings)
	sort.SliceStable(sorted, func(i, j int) bool {
		return severityRank(sorted[i].Severity) < severityRank(sorted[j].Severity)
	})
	rows := make([]table.Row, 0, len(sorted))
	for _, f := range sorted {
		rows = append(rows, table.Row{
			f.Severity,
			f.RuleID,
			filepath.Base(f.Repo),
			fmt.Sprintf("%s:%d", f.File, f.Line),
			f.Masked(),
		})
	}
	t := table.New(
		table.WithColumns(columns),
		table.WithRows(rows),
		table.WithFocused(true),
		table.WithHeight(min(12, max(3, len(rows)+1))),
	)
	styles := table.DefaultStyles()
	styles.Header = styles.Header.Bold(true).BorderStyle(lipgloss.NormalBorder()).BorderBottom(true).BorderForeground(lipgloss.Color("241"))
	styles.Selected = styles.Selected.Foreground(lipgloss.Color("229")).Background(lipgloss.Color("57"))
	t.SetStyles(styles)
	m.tbl = t
}

func severityRank(severity string) int {
	switch severity {
	case "CRITICAL":
		return 0
	case "HIGH":
		return 1
	case "MEDIUM":
		return 2
	case "LOW":
		return 3
	}
	return 4
}

func (m model) View() string {
	var b strings.Builder
	b.WriteString(styleTitle.Render("secretsweep") + styleSubtle.Render("  find and purge compromised keys") + "\n\n")

	switch m.phase {
	case phaseDiscover:
		b.WriteString(fmt.Sprintf("%s Discovering Git repositories under %s ...\n", m.spinner.View(), strings.Join(m.targets, ", ")))

	case phaseScan:
		b.WriteString(fmt.Sprintf("%s Trivy secret scan  [%d/%d]  %s\n",
			m.spinner.View(), m.scanIndex+1, len(m.repos), m.repos[m.scanIndex]))

	case phaseReview:
		secrets, unrecovered := UniqueSecrets(m.findings)
		b.WriteString(fmt.Sprintf("Repositories: %d    Findings: %d    Distinct secrets: %d\n",
			len(m.repos), len(m.findings), len(secrets)))
		if unrecovered > 0 {
			b.WriteString(styleWarn.Render(fmt.Sprintf("%d finding(s) could not be auto-recovered; review them manually.", unrecovered)) + "\n")
		}
		for _, e := range m.scanErrs {
			b.WriteString(styleWarn.Render("scan error: "+e) + "\n")
		}
		b.WriteString("\n")
		if len(m.findings) == 0 {
			b.WriteString(styleOK.Render("No secrets found in any working tree.") + "\n\n")
			b.WriteString(styleHelp.Render("[s] deep-scan history anyway requires keys — none recovered   [q] quit") + "\n")
		} else {
			b.WriteString(m.tbl.View() + "\n\n")
			b.WriteString(styleHelp.Render("[s] scan full history   [d] dry-run rewrite   [r] rewrite history   [↑/↓] browse   [q] quit") + "\n")
		}

	case phaseConfirm:
		secrets, _ := UniqueSecrets(m.findings)
		b.WriteString(styleDanger.Render("Rewrite mode permanently rewrites Git history in every matching repository.") + "\n")
		b.WriteString(fmt.Sprintf("%d distinct secret(s) across %d repositories will be replaced with REMOVED_API_KEY.\n", len(secrets), len(m.repos)))
		b.WriteString("Confirm the keys are revoked and backups exist.\n\n")
		b.WriteString("Type \"rewrite\" to continue, esc to go back:\n")
		b.WriteString(m.confirmInput.View() + "\n")

	case phaseRun:
		b.WriteString(fmt.Sprintf("%s Engine %s in progress...\n", m.spinner.View(), m.ranAction))
		b.WriteString(styleViewport.Render(m.viewport.View()) + "\n")
		b.WriteString(styleHelp.Render("[↑/↓] scroll   ctrl+c abort") + "\n")

	case phaseDone:
		if m.err != nil {
			b.WriteString(styleDanger.Render("Error: "+m.err.Error()) + "\n")
			b.WriteString(styleHelp.Render("[q] quit") + "\n")
			break
		}
		if len(m.repos) == 0 {
			b.WriteString("No Git repositories found under: " + strings.Join(m.targets, ", ") + "\n")
			b.WriteString(styleHelp.Render("[q] quit") + "\n")
			break
		}
		if len(m.engineLines) > 0 {
			b.WriteString(styleViewport.Render(m.viewport.View()) + "\n")
		}
		switch {
		case m.engineExit == 0 && m.ranAction != "":
			b.WriteString(styleOK.Render(fmt.Sprintf("Engine %s finished: everything is clear.", m.ranAction)) + "\n")
		case m.engineExit == 3:
			b.WriteString(styleWarn.Render("Compromised material found. Revoke the keys, back up, then run the rewrite.") + "\n")
		case m.engineExit == 4:
			b.WriteString(styleDanger.Render("Rewrite skipped or failed for at least one repository; inspect the log above.") + "\n")
		case m.engineExit > 0:
			b.WriteString(styleDanger.Render(fmt.Sprintf("Engine exited with status %d.", m.engineExit)) + "\n")
		}
		b.WriteString(styleHelp.Render("[b] back to findings   [q] quit") + "\n")
	}

	return b.String()
}

func runTUI(targets []string, enginePath string) error {
	p := tea.NewProgram(newModel(targets, enginePath), tea.WithAltScreen())
	_, err := p.Run()
	return err
}
