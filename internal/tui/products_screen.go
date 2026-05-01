package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/storage"
)

// productsLoadedMsg carries the result of the async ListProducts query.
type productsLoadedMsg struct {
	products []*domain.Product
}

// productsScreen lists products with Name | Owner | Updated columns.
// It loads the list asynchronously on Init and re-loads on demand via 'r'.
type productsScreen struct {
	store    storage.Storage
	products []*domain.Product
	cursor   int
	loading  bool
	loadErr  error
}

func newProductsScreen(store storage.Storage) productsScreen {
	return productsScreen{store: store, loading: store != nil}
}

func (p productsScreen) Title() string { return "Products" }

func (p productsScreen) Init() tea.Cmd {
	if p.store == nil {
		return nil
	}
	return loadProductsCmd(p.store)
}

func (p productsScreen) Update(msg tea.Msg) (screen, tea.Cmd) {
	switch msg := msg.(type) {
	case productsLoadedMsg:
		p.products = msg.products
		p.loading = false
		p.loadErr = nil
		if p.cursor >= len(p.products) {
			p.cursor = 0
		}
		return p, nil
	case errMsg:
		p.loading = false
		p.loadErr = msg.err
		return p, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			if p.cursor > 0 {
				p.cursor--
			}
			return p, nil
		case "down", "j":
			if p.cursor < len(p.products)-1 {
				p.cursor++
			}
			return p, nil
		case "home", "g":
			p.cursor = 0
			return p, nil
		case "end", "G":
			if len(p.products) > 0 {
				p.cursor = len(p.products) - 1
			}
			return p, nil
		case "r":
			if p.store == nil {
				return p, nil
			}
			p.loading = true
			p.loadErr = nil
			return p, loadProductsCmd(p.store)
		case "enter", "right", "l":
			if len(p.products) == 0 {
				return p, nil
			}
			selected := p.products[p.cursor]
			next := newProductDetailScreen(p.store, selected)
			return p, tea.Batch(
				func() tea.Msg { return pushScreenMsg{s: next} },
				next.Init(),
			)
		}
	}
	return p, nil
}

func (p productsScreen) View() string {
	var b strings.Builder
	b.WriteString(sectionHeaderStyle.Render("Products"))
	b.WriteString("\n\n")

	if p.store == nil {
		b.WriteString(errorStyle.Render("no database connected"))
		b.WriteString("\n")
		b.WriteString(helpStyle.Render("set --db-dsn or STATEBOUND_DB_DSN, then relaunch"))
		return b.String()
	}
	if p.loading {
		b.WriteString(dimStyle.Render("loading..."))
		return b.String()
	}
	if p.loadErr != nil {
		b.WriteString(errorStyle.Render("error: " + p.loadErr.Error()))
		b.WriteString("\n")
		b.WriteString(helpStyle.Render("press r to retry, q/esc to go back"))
		return b.String()
	}
	if len(p.products) == 0 {
		b.WriteString(dimStyle.Render("No products yet. Create one with `statebound product create <name>`."))
		b.WriteString("\n\n")
		b.WriteString(helpStyle.Render("press r to refresh, q/esc to go back"))
		return b.String()
	}

	header := fmt.Sprintf("  %-30s  %-20s  %-20s", "NAME", "OWNER", "UPDATED")
	b.WriteString(dimStyle.Render(header))
	b.WriteString("\n")

	for i, prod := range p.products {
		marker := "  "
		if i == p.cursor {
			marker = "> "
		}
		row := fmt.Sprintf("%s%-30s  %-20s  %-20s",
			marker,
			truncate(prod.Name, 30),
			truncate(prod.Owner, 20),
			prod.UpdatedAt.UTC().Format("2006-01-02 15:04:05"),
		)
		if i == p.cursor {
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

// loadProductsCmd returns a tea.Cmd that issues ListProducts and emits the
// result (or an errMsg) so the products screen can update without blocking
// the render loop.
func loadProductsCmd(store storage.Storage) tea.Cmd {
	return func() tea.Msg {
		ps, err := store.ListProducts(ensureContext())
		if err != nil {
			return errMsg{err: err}
		}
		return productsLoadedMsg{products: ps}
	}
}

// truncate clips s to n runes, appending "..." when clipped. Cheap and good
// enough for the Phase 1 column layout; we are not RTL-aware yet.
func truncate(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if len(s) <= n {
		return s
	}
	if n <= 3 {
		return s[:n]
	}
	return s[:n-3] + "..."
}
