package tui

import (
	"fmt"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/storage"
)

// evidenceListLimit caps the table size; matches the spec guidance for the
// section view (newest 50).
const evidenceListLimit = 50

// evidencePacksLoadedMsg carries the result of the async ListEvidencePacksByProduct
// fan-out for every known product. The screen merges the per-product slices
// in receive order; the final render sorts by GeneratedAt descending so the
// table is product-agnostic and "newest first" globally.
type evidencePacksLoadedMsg struct {
	packs []*domain.EvidencePack
}

// evidenceScreen lists evidence packs across all products, newest first.
// Pressing Enter on a row opens a small detail view with the metadata and
// the first 80 lines of the persisted content. The screen is intentionally
// read-only — exports are driven from the CLI (see `statebound evidence
// export`); this surface is for inspection only.
type evidenceScreen struct {
	store storage.Storage

	packs        []*domain.EvidencePack
	productNames map[domain.ID]string

	cursor  int
	loading bool
	loadErr error
}

func newEvidenceScreen(store storage.Storage) evidenceScreen {
	return evidenceScreen{
		store:        store,
		loading:      store != nil,
		productNames: map[domain.ID]string{},
	}
}

func (s evidenceScreen) Title() string { return "Evidence Packs" }

func (s evidenceScreen) Init() tea.Cmd {
	if s.store == nil {
		return nil
	}
	return tea.Batch(
		loadEvidencePacksCmd(s.store),
		loadProductNamesCmd(s.store),
	)
}

func (s evidenceScreen) Update(msg tea.Msg) (screen, tea.Cmd) {
	switch msg := msg.(type) {
	case evidencePacksLoadedMsg:
		s.packs = sortEvidencePacksDesc(msg.packs)
		s.loading = false
		s.loadErr = nil
		if s.cursor >= len(s.packs) {
			s.cursor = 0
		}
		return s, nil
	case productNamesLoadedMsg:
		if msg.names != nil {
			s.productNames = msg.names
		}
		return s, nil
	case errMsg:
		s.loading = false
		s.loadErr = msg.err
		return s, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			if s.cursor > 0 {
				s.cursor--
			}
			return s, nil
		case "down", "j":
			if s.cursor < len(s.packs)-1 {
				s.cursor++
			}
			return s, nil
		case "home", "g":
			s.cursor = 0
			return s, nil
		case "end", "G":
			if n := len(s.packs); n > 0 {
				s.cursor = n - 1
			}
			return s, nil
		case "r":
			if s.store == nil {
				return s, nil
			}
			s.loading = true
			s.loadErr = nil
			return s, tea.Batch(
				loadEvidencePacksCmd(s.store),
				loadProductNamesCmd(s.store),
			)
		case "enter", "right", "l":
			if len(s.packs) == 0 {
				return s, nil
			}
			pack := s.packs[s.cursor]
			next := newEvidenceDetailScreen(pack, s.productNames[pack.ProductID])
			return s, func() tea.Msg { return pushScreenMsg{s: next} }
		}
	}
	return s, nil
}

func (s evidenceScreen) View() string {
	var b strings.Builder
	b.WriteString(sectionHeaderStyle.Render("Evidence Packs"))
	b.WriteString("\n\n")

	if s.store == nil {
		b.WriteString(errorStyle.Render("no database connected"))
		b.WriteString("\n")
		b.WriteString(helpStyle.Render("set --db-dsn or STATEBOUND_DB_DSN, then relaunch"))
		return b.String()
	}
	if s.loading {
		b.WriteString(dimStyle.Render("loading..."))
		return b.String()
	}
	if s.loadErr != nil {
		b.WriteString(errorStyle.Render("error: " + s.loadErr.Error()))
		b.WriteString("\n")
		b.WriteString(helpStyle.Render("press r to retry, q/esc to go back"))
		return b.String()
	}
	if len(s.packs) == 0 {
		b.WriteString(dimStyle.Render("No evidence packs yet. Run `statebound evidence export --product <name>` to create one."))
		b.WriteString("\n\n")
		b.WriteString(helpStyle.Render("r to refresh, q/esc to go back"))
		return b.String()
	}

	header := fmt.Sprintf("  %-10s  %-20s  %-7s  %-9s  %-14s  %-19s",
		"ID", "PRODUCT", "VERSION", "FORMAT", "HASH", "GENERATED_AT")
	b.WriteString(dimStyle.Render(header))
	b.WriteString("\n")

	for i, p := range s.packs {
		marker := "  "
		if i == s.cursor {
			marker = "> "
		}
		productName := s.productNames[p.ProductID]
		if productName == "" {
			productName = shortID(p.ProductID)
		}
		row := fmt.Sprintf("%s%-10s  %-20s  v%-6d  %-9s  %-14s  %-19s",
			marker,
			shortID(p.ID),
			truncate(productName, 20),
			p.Sequence,
			truncate(p.Format, 9),
			truncate(p.ContentHash, 14),
			p.GeneratedAt.UTC().Format("2006-01-02 15:04:05"),
		)
		if i == s.cursor {
			b.WriteString(selectedRowStyle.Render(row))
		} else {
			b.WriteString(rowStyle.Render(row))
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")
	b.WriteString(helpStyle.Render("enter to open; r to refresh; q/esc to go back"))
	return b.String()
}

// loadEvidencePacksCmd fans out a ListEvidencePacksByProduct over every known
// product, then merges the slices into a single result message. We list
// products first so that an empty product table yields an empty pack list
// rather than a confusing error.
func loadEvidencePacksCmd(store storage.Storage) tea.Cmd {
	return func() tea.Msg {
		ctx := ensureContext()
		products, err := store.ListProducts(ctx)
		if err != nil {
			return errMsg{err: err}
		}
		var all []*domain.EvidencePack
		for _, p := range products {
			if p == nil {
				continue
			}
			packs, err := store.ListEvidencePacksByProduct(ctx, p.ID, evidenceListLimit)
			if err != nil {
				return errMsg{err: err}
			}
			all = append(all, packs...)
		}
		return evidencePacksLoadedMsg{packs: all}
	}
}

// sortEvidencePacksDesc orders by GeneratedAt descending (newest first), then
// by ID for stability when two packs share a timestamp.
func sortEvidencePacksDesc(in []*domain.EvidencePack) []*domain.EvidencePack {
	out := append([]*domain.EvidencePack(nil), in...)
	sort.SliceStable(out, func(i, j int) bool {
		ai, aj := out[i].GeneratedAt.UTC(), out[j].GeneratedAt.UTC()
		if !ai.Equal(aj) {
			return ai.After(aj)
		}
		return out[i].ID > out[j].ID
	})
	if len(out) > evidenceListLimit {
		out = out[:evidenceListLimit]
	}
	return out
}

// evidenceDetailScreen renders a single pack's metadata plus the first
// detailContentLineLimit lines of the persisted content blob. The screen is
// strictly read-only — there is no Esc-to-confirm flow because the user
// cannot mutate the pack from here.
const detailContentLineLimit = 80

type evidenceDetailScreen struct {
	pack        *domain.EvidencePack
	productName string
}

func newEvidenceDetailScreen(pack *domain.EvidencePack, productName string) evidenceDetailScreen {
	return evidenceDetailScreen{pack: pack, productName: productName}
}

func (s evidenceDetailScreen) Title() string {
	if s.pack == nil {
		return "Evidence Pack"
	}
	return fmt.Sprintf("Evidence Pack %s", shortID(s.pack.ID))
}

func (s evidenceDetailScreen) Init() tea.Cmd { return nil }

func (s evidenceDetailScreen) Update(msg tea.Msg) (screen, tea.Cmd) {
	if _, ok := msg.(tea.KeyMsg); !ok {
		return s, nil
	}
	// Any key press other than the global esc/q (handled by the model) is a no-op.
	return s, nil
}

func (s evidenceDetailScreen) View() string {
	var b strings.Builder
	if s.pack == nil {
		b.WriteString(errorStyle.Render("missing pack"))
		return b.String()
	}
	productName := s.productName
	if productName == "" {
		productName = shortID(s.pack.ProductID)
	}
	b.WriteString(sectionHeaderStyle.Render(fmt.Sprintf("Evidence Pack — %s v%d", productName, s.pack.Sequence)))
	b.WriteString("\n\n")
	fmt.Fprintf(&b, "  ID:                  %s\n", s.pack.ID)
	fmt.Fprintf(&b, "  Format:              %s\n", s.pack.Format)
	fmt.Fprintf(&b, "  Content hash:        sha256:%s\n", s.pack.ContentHash)
	fmt.Fprintf(&b, "  Approved version id: %s\n", s.pack.ApprovedVersionID)
	fmt.Fprintf(&b, "  Generated at:        %s\n", s.pack.GeneratedAt.UTC().Format("2006-01-02T15:04:05Z"))
	fmt.Fprintf(&b, "  Generated by:        %s (%s)\n", s.pack.GeneratedBy.Subject, s.pack.GeneratedBy.Kind)
	b.WriteString("\n")
	b.WriteString(dimStyle.Render(fmt.Sprintf("  --- content (first %d lines) ---", detailContentLineLimit)))
	b.WriteString("\n")
	for _, line := range firstNLines(string(s.pack.Content), detailContentLineLimit) {
		b.WriteString("  ")
		b.WriteString(line)
		b.WriteString("\n")
	}
	b.WriteString("\n")
	b.WriteString(helpStyle.Render("q/esc to go back"))
	return b.String()
}

// firstNLines splits s on newlines and returns up to n lines. Callers render
// content verbatim (no markdown unwrapping), so what the user sees in the
// detail view is exactly what would be persisted on disk by `evidence show`.
func firstNLines(s string, n int) []string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return lines
}
