package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

const (
	// templateSuffix marks one man(7) template beside its rendered page.
	templateSuffix = ".in"
	// directivePrefix introduces one help-embedding directive line.
	directivePrefix = `.\" @cobra `
	// helpTimeout bounds one product help invocation.
	helpTimeout = 10 * time.Second
)

var (
	// productBinaries is the closed set of commands a template may embed.
	productBinaries = []string{"dkim2-dsn-propagator", "dkim2-exim", "dkim2-milter", "dkim2ctl", "dkim2d"}
	// commandWord accepts one plain subcommand name and nothing flag-like.
	commandWord = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	// manualPage matches a rendered page name with a numeric section.
	manualPage = regexp.MustCompile(`^[a-z0-9-]+\.[1-9]$`)
	// columnGap separates a Cobra flag specification from its description.
	columnGap = regexp.MustCompile(`\s{2,}`)

	errStalePages = errors.New("manual pages are stale; run make man")
)

// helpSource returns the exact help text of one product command path.
type helpSource interface {
	Help(binary string, args []string) (string, error)
}

// binaryHelp runs built product binaries from one directory.
type binaryHelp struct {
	dir string
}

// Help runs "<binary> <args...> --help" with an empty environment and returns
// its standard output; any failure, stderr output, or empty help fails closed.
func (h binaryHelp) Help(binary string, args []string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), helpTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, filepath.Join(h.dir, binary), append(slices.Clone(args), "--help")...)
	command.Env = []string{"LC_ALL=C"}
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return "", fmt.Errorf("%s help failed: %w", binary, err)
	}
	if stderr.Len() != 0 || stdout.Len() == 0 {
		return "", fmt.Errorf("%s help produced no clean output", binary)
	}
	return stdout.String(), nil
}

// pageGenerator owns the template directory, the page directory, and the
// help source used to render every page.
type pageGenerator struct {
	sourceDir string
	outputDir string
	help      helpSource
}

// newPageGenerator binds the repository layout to binaries in binDir.
func newPageGenerator(rootPath, binDir string) (*pageGenerator, error) {
	if !filepath.IsAbs(binDir) {
		return nil, errors.New("-bin must be absolute")
	}
	outputDir := filepath.Join(rootPath, "docs", "man")
	return &pageGenerator{
		sourceDir: filepath.Join(outputDir, "src"),
		outputDir: outputDir,
		help:      binaryHelp{dir: binDir},
	}, nil
}

// renderAll renders every template and returns the pages keyed by file name.
func (g *pageGenerator) renderAll() (map[string][]byte, error) {
	sources, err := filepath.Glob(filepath.Join(g.sourceDir, "*"+templateSuffix))
	if err != nil {
		return nil, err
	}
	if len(sources) == 0 {
		return nil, errors.New("no manual page templates found")
	}
	pages := make(map[string][]byte, len(sources))
	for _, source := range sources {
		name := strings.TrimSuffix(filepath.Base(source), templateSuffix)
		if !manualPage.MatchString(name) {
			return nil, fmt.Errorf("%s: template name must be <page>.<section>%s", filepath.Base(source), templateSuffix)
		}
		template, err := os.ReadFile(source)
		if err != nil {
			return nil, err
		}
		page, err := renderPage(name, template, g.help)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Base(source), err)
		}
		pages[name] = page
	}
	return pages, nil
}

// write renders every template and replaces the committed pages.
func (g *pageGenerator) write() error {
	pages, err := g.renderAll()
	if err != nil {
		return err
	}
	for _, name := range slices.Sorted(maps.Keys(pages)) {
		if err := os.WriteFile(filepath.Join(g.outputDir, name), pages[name], 0o644); err != nil {
			return err
		}
	}
	return nil
}

// check compares every rendering with its committed page and rejects pages
// that have no template, so the page set cannot drift in either direction.
func (g *pageGenerator) check() error {
	pages, err := g.renderAll()
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(g.outputDir)
	if err != nil {
		return err
	}
	stale := false
	for _, entry := range entries {
		if entry.IsDir() || !manualPage.MatchString(entry.Name()) {
			continue
		}
		if _, ok := pages[entry.Name()]; !ok {
			fmt.Fprintf(os.Stderr, "mangen: %s has no template\n", entry.Name())
			stale = true
		}
	}
	for _, name := range slices.Sorted(maps.Keys(pages)) {
		committed, err := os.ReadFile(filepath.Join(g.outputDir, name))
		if err != nil || !bytes.Equal(committed, pages[name]) {
			fmt.Fprintf(os.Stderr, "mangen: %s is stale\n", name)
			stale = true
		}
	}
	if stale {
		return errStalePages
	}
	return nil
}

// renderPage expands every directive in one template. Templates must be
// ASCII so the pages render identically under every man(1) implementation.
func renderPage(name string, template []byte, help helpSource) ([]byte, error) {
	for _, b := range template {
		if b > 0x7e || (b < 0x20 && b != '\n') {
			return nil, errors.New("template must be printable ASCII")
		}
	}
	var out strings.Builder
	fmt.Fprintf(&out, ".\\\" Code generated by mangen from docs/man/src/%s%s; DO NOT EDIT.\n", name, templateSuffix)
	for line := range strings.Lines(string(template)) {
		line = strings.TrimSuffix(line, "\n")
		directive, ok := strings.CutPrefix(line, directivePrefix)
		if !ok {
			out.WriteString(line)
			out.WriteByte('\n')
			continue
		}
		block, err := expandDirective(strings.Fields(directive), help)
		if err != nil {
			return nil, err
		}
		out.WriteString(block)
	}
	return []byte(out.String()), nil
}

// expandDirective renders one "<Section> <binary> [subcommand...]" directive.
// Section names use "_" for spaces, for example Global_Flags.
func expandDirective(fields []string, help helpSource) (string, error) {
	if len(fields) < 2 {
		return "", errors.New("directive needs a section and a binary")
	}
	section := strings.ReplaceAll(fields[0], "_", " ")
	binary, args := fields[1], fields[2:]
	if !slices.Contains(productBinaries, binary) {
		return "", fmt.Errorf("unknown binary %q", binary)
	}
	for _, arg := range args {
		if !commandWord.MatchString(arg) {
			return "", fmt.Errorf("invalid subcommand %q", arg)
		}
	}
	text, err := help.Help(binary, args)
	if err != nil {
		return "", err
	}
	lines, err := helpSection(text, section)
	if err != nil {
		return "", fmt.Errorf("%s %s: %w", binary, strings.Join(args, " "), err)
	}
	switch {
	case section == "Usage":
		return renderSynopsis(lines), nil
	case strings.HasSuffix(section, "Flags"):
		return renderFlags(lines)
	default:
		return "", fmt.Errorf("unsupported section %q", section)
	}
}

// helpSection returns the trimmed lines of one "<Name>:" help block, which
// ends at the next blank line.
func helpSection(text, name string) ([]string, error) {
	var lines []string
	inside := false
	for line := range strings.Lines(text) {
		line = strings.TrimRight(line, " \n")
		if !inside {
			inside = line == name+":"
			continue
		}
		if line == "" {
			break
		}
		lines = append(lines, strings.TrimSpace(line))
	}
	if len(lines) == 0 {
		return nil, fmt.Errorf("help has no %q section", name)
	}
	return lines, nil
}

// renderSynopsis renders usage lines as left-aligned, unhyphenated
// paragraphs whose continuation lines hang under the command name.
func renderSynopsis(lines []string) string {
	var out strings.Builder
	out.WriteString(".ad l\n.nh\n.in +4n\n")
	for i, line := range lines {
		if i > 0 {
			out.WriteString(".br\n")
		}
		command, rest, _ := strings.Cut(line, " ")
		out.WriteString(".ti -4n\n")
		out.WriteString(`\fB` + roffEscape(command) + `\fR`)
		if rest != "" {
			out.WriteString(" " + roffEscape(rest))
		}
		out.WriteByte('\n')
	}
	out.WriteString(".in -4n\n.hy\n.ad\n")
	return out.String()
}

// renderFlags renders Cobra flag lines as a tagged paragraph list.
func renderFlags(lines []string) (string, error) {
	var out strings.Builder
	for _, line := range lines {
		parts := columnGap.Split(line, 2)
		if len(parts) != 2 || !strings.HasPrefix(parts[0], "-") {
			return "", fmt.Errorf("unrecognized flag line %q", line)
		}
		names, argument := splitFlagSpec(parts[0])
		out.WriteString(".TP\n")
		for i, name := range names {
			if i > 0 {
				out.WriteString(", ")
			}
			out.WriteString(`\fB` + roffEscape(name) + `\fR`)
		}
		if argument != "" {
			out.WriteString(` \fI` + roffEscape(argument) + `\fR`)
		}
		out.WriteByte('\n')
		out.WriteString(roffLine(parts[1]))
		out.WriteByte('\n')
	}
	return out.String(), nil
}

// splitFlagSpec splits "-h, --help" or "--config string" into flag names and
// the optional value placeholder.
func splitFlagSpec(spec string) ([]string, string) {
	names := strings.Split(spec, ", ")
	last := names[len(names)-1]
	if name, argument, ok := strings.Cut(last, " "); ok {
		names[len(names)-1] = name
		return names, argument
	}
	return names, ""
}

// roffEscape neutralizes backslashes and marks hyphens as minus signs so
// flags render as typable ASCII.
func roffEscape(text string) string {
	return strings.NewReplacer(`\`, `\e`, "-", `\-`).Replace(text)
}

// roffLine escapes one text line and guards a leading control character.
func roffLine(text string) string {
	escaped := roffEscape(text)
	if strings.HasPrefix(escaped, ".") || strings.HasPrefix(escaped, "'") {
		return `\&` + escaped
	}
	return escaped
}
