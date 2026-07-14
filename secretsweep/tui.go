package main

import (
	"bytes"
	"fmt"
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
	phaseSearch
	phaseReplacement
	phasePreview
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
	styleInfo     = lipgloss.NewStyle().Foreground(lipgloss.Color("81"))
	styleCritical = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("196"))
	styleHigh     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("208"))
	styleMedium   = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	styleLow      = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
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
	targets   []string
	extraKeys []string

	phase   phase
	spinner spinner.Model
	width   int
	height  int

	repos     []string
	scanIndex int
	findings  []Finding
	scanErrs  []string

	tbl          table.Model
	confirmInput textinput.Model
	searchInput  textinput.Model
	replaceInput textinput.Model
	review       ReviewState
	pendingPlan  CleanupPlan
	notice       string

	viewport    viewport.Model
	engineLines []string
	engineCh    chan engineEvMsg
	engineExit  int
	ranAction   EngineAction

	err error
}

func newModel(targets, extraKeys []string) model {
	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("212"))

	ti := textinput.New()
	ti.Placeholder = "apply"
	ti.CharLimit = 16
	ti.Width = 24

	search := textinput.New()
	search.Placeholder = "severity, rule, repository, or path"
	search.CharLimit = 160
	search.Width = 52

	replace := textinput.New()
	replace.Placeholder = defaultReplacement
	replace.CharLimit = 256
	replace.Width = 52

	vp := viewport.New(80, 16)

	return model{
		targets:      targets,
		extraKeys:    extraKeys,
		phase:        phaseDiscover,
		spinner:      sp,
		confirmInput: ti,
		searchInput:  search,
		replaceInput: replace,
		viewport:     vp,
		engineExit:   -1,
	}
}

func (m *model) enterReview() {
	findings := append([]Finding(nil), m.findings...)
	for i, secret := range m.extraKeys {
		findings = append(findings, Finding{
			File:     fmt.Sprintf("key-file entry %d", i+1),
			RuleID:   "manual-key",
			Title:    "Explicit history-only key",
			Severity: "MANUAL",
			Secret:   secret,
		})
	}
	sort.SliceStable(findings, func(i, j int) bool {
		return severityRank(findings[i].Severity) < severityRank(findings[j].Severity)
	})
	m.review = NewReviewState(findings)
	m.phase = phaseReview
	m.notice = ""
	m.rebuildTable()
}

// allSecrets is the full set of keys to act on: those recovered from Trivy
// findings plus any supplied via --key-file.
func (m model) allSecrets() []string {
	recovered, _ := UniqueSecrets(m.findings)
	return mergeSecrets(recovered, m.extraKeys)
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
	plan, err := BuildCleanupPlan(m.review)
	if err != nil {
		m.notice = humanPlanError(err)
		return nil
	}
	m.pendingPlan = plan
	ch := make(chan engineEvMsg, 256)
	m.engineCh = ch
	m.engineLines = nil
	m.ranAction = action
	m.phase = phaseRun

	repos := m.repos
	go func() {
		w := &channelWriter{ch: ch}
		code := RunCleanupPlan(w, action, plan, repos)
		w.flush()
		ch <- engineEvMsg{done: true, exit: code}
		close(ch)
	}()
	return listenEngine(ch)
}

func humanPlanError(err error) string {
	message := err.Error()
	if strings.HasPrefix(message, "select at least one") {
		return "Select at least one recovered finding before continuing."
	}
	return message
}

// channelWriter is an io.Writer that forwards each complete line written to it
// as an engineEvMsg on ch, so RunEngine's streamed output feeds the viewport.
type channelWriter struct {
	ch  chan engineEvMsg
	buf []byte
}

func (w *channelWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 {
			break
		}
		w.ch <- engineEvMsg{line: string(w.buf[:i])}
		w.buf = w.buf[i+1:]
	}
	return len(p), nil
}

func (w *channelWriter) flush() {
	if len(w.buf) > 0 {
		w.ch <- engineEvMsg{line: string(w.buf)}
		w.buf = nil
	}
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
			if len(m.extraKeys) == 0 {
				m.err = fmt.Errorf("trivy is not installed; install it with: brew install trivy (or pass --key-file)")
				m.phase = phaseDone
				return m, nil
			}
			// No Trivy, but --key-file supplied: skip discovery, act on those keys.
			m.enterReview()
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
		m.enterReview()
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
	case phaseSearch:
		switch msg.String() {
		case "esc", "enter":
			m.phase = phaseReview
			m.searchInput.Blur()
			m.rebuildTable()
			return m, nil
		case "ctrl+c":
			return m, tea.Quit
		case "ctrl+u":
			m.searchInput.SetValue("")
			m.review.SetQuery("")
			m.rebuildTable()
			return m, nil
		}
		var cmd tea.Cmd
		m.searchInput, cmd = m.searchInput.Update(msg)
		m.review.SetQuery(m.searchInput.Value())
		m.rebuildTable()
		return m, cmd

	case phaseReplacement:
		switch msg.String() {
		case "esc":
			m.phase = phaseReview
			m.replaceInput.Blur()
			m.notice = "Replacement edit cancelled."
			return m, nil
		case "ctrl+c":
			return m, tea.Quit
		case "ctrl+u":
			m.replaceInput.SetValue("")
			return m, nil
		case "enter":
			if err := ValidateReplacement(m.replaceInput.Value(), m.allSecrets()); err != nil {
				m.notice = err.Error()
				return m, nil
			}
			m.review.Replacement = m.replaceInput.Value()
			m.replaceInput.Blur()
			m.phase = phaseReview
			m.notice = "Replacement updated. Preview the plan before applying."
			return m, nil
		}
		var cmd tea.Cmd
		m.replaceInput, cmd = m.replaceInput.Update(msg)
		return m, cmd

	case phasePreview:
		switch msg.String() {
		case "esc", "b":
			m.phase = phaseReview
			m.notice = ""
			return m, nil
		case "d":
			return m, tea.Batch(m.spinner.Tick, m.startEngine(ActionDryRun))
		case "r", "enter":
			if !FilterRepoAvailable() {
				m.notice = "rewrite requires git-filter-repo; install it before applying"
				return m, nil
			}
			m.phase = phaseConfirm
			m.confirmInput.Reset()
			m.confirmInput.Focus()
			m.notice = ""
			return m, textinput.Blink
		case "ctrl+c", "q":
			return m, tea.Quit
		}
		var cmd tea.Cmd
		m.viewport, cmd = m.viewport.Update(msg)
		return m, cmd

	case phaseConfirm:
		switch msg.String() {
		case "esc":
			m.phase = phasePreview
			m.confirmInput.Reset()
			return m, nil
		case "enter":
			if m.confirmInput.Value() == "apply" {
				m.confirmInput.Reset()
				return m, tea.Batch(m.spinner.Tick, m.startEngine(ActionRewrite))
			}
			m.confirmInput.Reset()
			m.notice = `Type "apply" exactly to authorize the rewrite.`
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
		case "/":
			m.phase = phaseSearch
			m.searchInput.SetValue(m.review.Query())
			m.searchInput.CursorEnd()
			m.searchInput.Focus()
			m.notice = ""
			return m, textinput.Blink
		case "up", "k":
			m.review.Move(-1)
			m.rebuildTable()
			return m, nil
		case "down", "j":
			m.review.Move(1)
			m.rebuildTable()
			return m, nil
		case "pgup":
			m.review.Move(-10)
			m.rebuildTable()
			return m, nil
		case "pgdown":
			m.review.Move(10)
			m.rebuildTable()
			return m, nil
		case " ":
			if err := m.review.CycleCurrentAction(); err != nil {
				m.notice = err.Error()
			} else {
				m.notice = ""
			}
			m.rebuildTable()
			return m, nil
		case "e":
			m.phase = phaseReplacement
			m.replaceInput.SetValue(m.review.Replacement)
			m.replaceInput.CursorEnd()
			m.replaceInput.Focus()
			m.notice = ""
			return m, textinput.Blink
		case "p", "enter":
			plan, err := BuildCleanupPlan(m.review)
			if err != nil {
				m.notice = humanPlanError(err)
				return m, nil
			}
			m.pendingPlan = plan
			m.viewport.SetContent(renderPlan(plan, m.repos))
			m.viewport.GotoTop()
			m.phase = phasePreview
			m.notice = ""
			return m, nil
		case "s":
			return m, tea.Batch(m.spinner.Tick, m.startEngine(ActionScan))
		case "d":
			return m, tea.Batch(m.spinner.Tick, m.startEngine(ActionDryRun))
		}
		return m, nil

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
	tableWidth := width
	if width >= 90 {
		tableWidth = width*2/3 - 3
	}
	fileWidth := max(18, tableWidth-58)
	columns := []table.Column{
		{Title: "Action", Width: 11},
		{Title: "Severity", Width: 9},
		{Title: "Rule", Width: 16},
		{Title: "Repository", Width: 16},
		{Title: "File:Line", Width: fileWidth},
	}
	visible := m.review.Visible()
	rows := make([]table.Row, 0, len(visible))
	for _, f := range visible {
		repoName := filepath.Base(f.Repo)
		if f.Repo == "" {
			repoName = "all repos"
		}
		rows = append(rows, table.Row{
			actionLabel(m.review.ActionFor(f)),
			f.Severity,
			f.RuleID,
			repoName,
			fmt.Sprintf("%s:%d", f.File, f.Line),
		})
	}
	t := table.New(
		table.WithColumns(columns),
		table.WithRows(rows),
		table.WithFocused(true),
		table.WithHeight(min(max(6, m.height-14), max(3, len(rows)+1))),
	)
	styles := table.DefaultStyles()
	styles.Header = styles.Header.Bold(true).BorderStyle(lipgloss.NormalBorder()).BorderBottom(true).BorderForeground(lipgloss.Color("241"))
	styles.Selected = styles.Selected.Foreground(lipgloss.Color("229")).Background(lipgloss.Color("57"))
	t.SetStyles(styles)
	if len(rows) > 0 {
		t.SetCursor(min(m.review.Cursor(), len(rows)-1))
	}
	m.tbl = t
}

func actionLabel(action ReviewAction) string {
	switch action {
	case ActionReplace:
		return "● replace"
	case ActionDeleteFile:
		return "× delete"
	default:
		return "○ none"
	}
}

func renderPlan(plan CleanupPlan, repos []string) string {
	var b strings.Builder
	b.WriteString("Exact cleanup plan\n\n")
	fmt.Fprintf(&b, "REPLACE  %d selected secret(s) everywhere with %s\n", len(plan.Replacements), replacementSummary(plan.Replacements))
	deleteCount := 0
	for _, repo := range repos {
		for _, file := range plan.DeletePaths[repo] {
			deleteCount++
			fmt.Fprintf(&b, "DELETE   %s from all history in %s\n", file, repo)
		}
	}
	if deleteCount == 0 {
		b.WriteString("DELETE   no files\n")
	}
	b.WriteString("\nSafety checks\n")
	b.WriteString("• Dirty working repositories will be skipped.\n")
	b.WriteString("• Every selected secret is verified against all remaining Git objects.\n")
	b.WriteString("• Deleted paths are checked against reachable history.\n")
	b.WriteString("• No remote is pushed automatically.\n")
	return b.String()
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

func severityBadge(severity string) string {
	switch severity {
	case "CRITICAL":
		return styleCritical.Render(severity)
	case "HIGH":
		return styleHigh.Render(severity)
	case "MEDIUM":
		return styleMedium.Render(severity)
	case "LOW":
		return styleLow.Render(severity)
	default:
		return styleInfo.Render(severity)
	}
}

func (m model) reviewView(searching bool) string {
	var b strings.Builder
	visible := m.review.Visible()
	all := m.allSecrets()
	_, unrecovered := UniqueSecrets(m.findings)
	fmt.Fprintf(&b, "Repositories: %d    Findings: %d    Visible: %d    Selected: %d    Distinct secrets: %d\n",
		len(m.repos), len(m.findings)+len(m.extraKeys), len(visible), m.review.SelectedCount(), len(all))
	if m.review.Query() != "" {
		b.WriteString(styleInfo.Render(fmt.Sprintf("Filter: %q", m.review.Query())) + "\n")
	}
	if unrecovered > 0 {
		b.WriteString(styleWarn.Render(fmt.Sprintf("%d finding(s) could not be recovered and cannot be selected automatically.", unrecovered)) + "\n")
	}
	for _, scanErr := range m.scanErrs {
		b.WriteString(styleWarn.Render("scan error: "+scanErr) + "\n")
	}
	if m.notice != "" {
		b.WriteString(styleWarn.Render(m.notice) + "\n")
	}
	if searching {
		b.WriteString("\nSearch: " + m.searchInput.View() + "\n")
		b.WriteString(styleHelp.Render("Type to filter   [ctrl+u] clear   [enter/esc] return to report") + "\n")
	}
	b.WriteString("\n")
	if len(visible) == 0 {
		if len(all) == 0 {
			b.WriteString(styleOK.Render("No recoverable secrets found in any working tree.") + "\n")
		} else {
			b.WriteString(styleWarn.Render("No findings match the current search.") + "\n")
		}
	} else {
		detail := m.findingDetail()
		if m.width >= 90 {
			leftWidth := m.width*2/3 - 3
			left := lipgloss.NewStyle().Width(leftWidth).Render(m.tbl.View())
			right := styleViewport.Width(max(24, m.width-leftWidth-7)).Render(detail)
			b.WriteString(lipgloss.JoinHorizontal(lipgloss.Top, left, "  ", right))
		} else {
			b.WriteString(m.tbl.View())
			b.WriteString("\n")
			b.WriteString(styleViewport.Render(detail))
		}
		b.WriteString("\n")
	}
	if !searching {
		b.WriteString(styleHelp.Render("[↑/↓] navigate   [space] none→replace→delete   [/] search   [e] replacement   [p] preview   [s] history scan   [d] dry-run   [q] quit") + "\n")
	}
	return b.String()
}

func (m model) findingDetail() string {
	finding, ok := m.review.Current()
	if !ok {
		return "No finding selected"
	}
	var b strings.Builder
	b.WriteString(severityBadge(finding.Severity) + "  " + styleTitle.Render(finding.RuleID) + "\n\n")
	b.WriteString(finding.Title + "\n")
	if finding.Repo == "" {
		b.WriteString("Repository: all discovered repositories\n")
	} else {
		b.WriteString("Repository: " + filepath.Base(finding.Repo) + "\n")
	}
	fmt.Fprintf(&b, "Location: %s:%d\n", finding.File, finding.Line)
	b.WriteString("Secret: " + finding.Masked() + "\n")
	b.WriteString("Action: " + actionLabel(m.review.ActionFor(finding)) + "\n\n")
	switch m.review.ActionFor(finding) {
	case ActionReplace:
		b.WriteString("Replace this secret in every repository and all Git history.")
	case ActionDeleteFile:
		b.WriteString("Delete this path from this repository's history and replace the secret everywhere else.")
	default:
		b.WriteString("No change will be made for this finding.")
	}
	return b.String()
}

func (m model) View() string {
	var b strings.Builder
	b.WriteString(styleTitle.Render("secretsweep") + styleSubtle.Render("  find and purge compromised keys") + "\n\n")

	switch m.phase {
	case phaseDiscover:
		fmt.Fprintf(&b, "%s Discovering Git repositories under %s ...\n", m.spinner.View(), strings.Join(m.targets, ", "))

	case phaseScan:
		fmt.Fprintf(&b, "%s Trivy secret scan  [%d/%d]  %s\n",
			m.spinner.View(), m.scanIndex+1, len(m.repos), m.repos[m.scanIndex])
		fmt.Fprintf(&b, "%s\n", styleInfo.Render(fmt.Sprintf("Found: %d", len(m.findings))))
		if len(m.findings) > 0 {
			latest := m.findings[len(m.findings)-1]
			fmt.Fprintf(&b, "Latest: %s  %s:%d  %s\n", severityBadge(latest.Severity), latest.File, latest.Line, latest.Masked())
		}

	case phaseReview:
		b.WriteString(m.reviewView(false))

	case phaseSearch:
		b.WriteString(m.reviewView(true))

	case phaseReplacement:
		b.WriteString(styleInfo.Render("Replacement text") + "\n")
		b.WriteString("The selected compromised value will be replaced everywhere it occurs.\n")
		b.WriteString("Use a plain, non-secret, single-line marker.\n\n")
		b.WriteString(m.replaceInput.View() + "\n")
		if m.notice != "" {
			b.WriteString(styleWarn.Render(m.notice) + "\n")
		}
		b.WriteString(styleHelp.Render("[enter] save   [ctrl+u] clear   [esc] cancel") + "\n")

	case phasePreview:
		b.WriteString(styleInfo.Render("Review before changing history") + "\n")
		b.WriteString(styleViewport.Render(m.viewport.View()) + "\n")
		if m.notice != "" {
			b.WriteString(styleWarn.Render(m.notice) + "\n")
		}
		b.WriteString(styleHelp.Render("[d] execute dry-run   [r/enter] continue to confirmation   [b/esc] back") + "\n")

	case phaseConfirm:
		b.WriteString(styleDanger.Render("Rewrite mode permanently rewrites Git history in every matching repository.") + "\n")
		fmt.Fprintf(&b, "%d selected secret(s) across %d repositories will be replaced with %s.\n", len(m.pendingPlan.Replacements), len(m.repos), replacementSummary(m.pendingPlan.Replacements))
		deleteCount := 0
		for _, paths := range m.pendingPlan.DeletePaths {
			deleteCount += len(paths)
		}
		if deleteCount > 0 {
			fmt.Fprintf(&b, "%d selected file path(s) will be removed from their repository history.\n", deleteCount)
		}
		b.WriteString("Confirm the keys are revoked and backups exist.\n\n")
		b.WriteString("Type \"apply\" to continue, esc to go back:\n")
		b.WriteString(m.confirmInput.View() + "\n")
		if m.notice != "" {
			b.WriteString(styleWarn.Render(m.notice) + "\n")
		}

	case phaseRun:
		fmt.Fprintf(&b, "%s Engine %s in progress...\n", m.spinner.View(), m.ranAction)
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

func runTUI(targets, extraKeys []string) error {
	p := tea.NewProgram(newModel(targets, extraKeys), tea.WithAltScreen())
	_, err := p.Run()
	return err
}
