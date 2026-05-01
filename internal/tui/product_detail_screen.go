package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/storage"
)

// productTab indexes the tabs in the product detail screen.
type productTab int

const (
	tabOverview productTab = iota
	tabAssets
	tabAssetScopes
	tabEntitlements
	tabServiceAccounts
	tabGlobalObjects
	tabAuthorizations
)

// productTabLabels is the human-readable tab strip, in display order.
var productTabLabels = []string{
	"Overview",
	"Assets",
	"Asset Scopes",
	"Entitlements",
	"Service Accounts",
	"Global Objects",
	"Authorizations",
}

// Async result message types per tab. Keeping them separate avoids a giant
// type switch and makes it obvious which command produced which payload.
type assetsLoadedMsg struct {
	productID domain.ID
	assets    []*domain.Asset
}
type assetScopesLoadedMsg struct {
	productID domain.ID
	scopes    []*domain.AssetScope
}
type entitlementsLoadedMsg struct {
	productID    domain.ID
	entitlements []*domain.Entitlement
}
type serviceAccountsLoadedMsg struct {
	productID       domain.ID
	serviceAccounts []*domain.ServiceAccount
}
type globalObjectsLoadedMsg struct {
	productID domain.ID
	objects   []*domain.GlobalObject
}
type authzSummaryLoadedMsg struct {
	productID domain.ID
	// counts keyed by parent name (e.g. "ent:payments-prod-readonly").
	entCounts map[string]int
	saCounts  map[string]int
	gobCounts map[string]int
	totalEnt  int
	totalSA   int
	totalGOB  int
}

// productDetailScreen shows a tabbed view of a single product's children.
// Each tab loads its data lazily on first view and caches the result.
type productDetailScreen struct {
	store   storage.Storage
	product *domain.Product
	tab     productTab

	// Per-tab cached state.
	assetsLoaded bool
	assets       []*domain.Asset
	assetsErr    error

	scopesLoaded bool
	scopes       []*domain.AssetScope
	scopesErr    error

	entitlementsLoaded bool
	entitlements       []*domain.Entitlement
	entitlementsErr    error

	serviceAccountsLoaded bool
	serviceAccounts       []*domain.ServiceAccount
	serviceAccountsErr    error

	globalObjectsLoaded bool
	globalObjects       []*domain.GlobalObject
	globalObjectsErr    error

	authzLoaded bool
	authzErr    error
	authzSumm   authzSummaryLoadedMsg
}

func newProductDetailScreen(store storage.Storage, p *domain.Product) productDetailScreen {
	return productDetailScreen{store: store, product: p}
}

func (s productDetailScreen) Title() string {
	if s.product == nil {
		return "Product"
	}
	return s.product.Name
}

func (s productDetailScreen) Init() tea.Cmd {
	// Eagerly trigger the active tab's loader; for the default Overview tab
	// there is no async work to do.
	return s.loadCmdForTab(s.tab)
}

func (s productDetailScreen) Update(msg tea.Msg) (screen, tea.Cmd) {
	switch msg := msg.(type) {
	case assetsLoadedMsg:
		if s.product != nil && msg.productID == s.product.ID {
			s.assets = msg.assets
			s.assetsLoaded = true
			s.assetsErr = nil
		}
		return s, nil
	case assetScopesLoadedMsg:
		if s.product != nil && msg.productID == s.product.ID {
			s.scopes = msg.scopes
			s.scopesLoaded = true
			s.scopesErr = nil
		}
		return s, nil
	case entitlementsLoadedMsg:
		if s.product != nil && msg.productID == s.product.ID {
			s.entitlements = msg.entitlements
			s.entitlementsLoaded = true
			s.entitlementsErr = nil
			// Once entitlements/SAs/GOs are loaded we can build the authz
			// summary; trigger a fetch if we are on that tab and have the
			// pre-requisites.
			if s.tab == tabAuthorizations {
				return s, s.loadAuthzSummaryIfReady()
			}
		}
		return s, nil
	case serviceAccountsLoadedMsg:
		if s.product != nil && msg.productID == s.product.ID {
			s.serviceAccounts = msg.serviceAccounts
			s.serviceAccountsLoaded = true
			s.serviceAccountsErr = nil
			if s.tab == tabAuthorizations {
				return s, s.loadAuthzSummaryIfReady()
			}
		}
		return s, nil
	case globalObjectsLoadedMsg:
		if s.product != nil && msg.productID == s.product.ID {
			s.globalObjects = msg.objects
			s.globalObjectsLoaded = true
			s.globalObjectsErr = nil
			if s.tab == tabAuthorizations {
				return s, s.loadAuthzSummaryIfReady()
			}
		}
		return s, nil
	case authzSummaryLoadedMsg:
		if s.product != nil && msg.productID == s.product.ID {
			s.authzSumm = msg
			s.authzLoaded = true
			s.authzErr = nil
		}
		return s, nil
	case errMsg:
		// Attribute the error to whichever tab the user is on. Phase 1 keeps
		// this simple; later we can tag commands with their target tab.
		switch s.tab {
		case tabAssets:
			s.assetsErr = msg.err
			s.assetsLoaded = true
		case tabAssetScopes:
			s.scopesErr = msg.err
			s.scopesLoaded = true
		case tabEntitlements:
			s.entitlementsErr = msg.err
			s.entitlementsLoaded = true
		case tabServiceAccounts:
			s.serviceAccountsErr = msg.err
			s.serviceAccountsLoaded = true
		case tabGlobalObjects:
			s.globalObjectsErr = msg.err
			s.globalObjectsLoaded = true
		case tabAuthorizations:
			s.authzErr = msg.err
			s.authzLoaded = true
		}
		return s, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "1":
			return s.switchTab(tabOverview)
		case "2":
			return s.switchTab(tabAssets)
		case "3":
			return s.switchTab(tabAssetScopes)
		case "4":
			return s.switchTab(tabEntitlements)
		case "5":
			return s.switchTab(tabServiceAccounts)
		case "6":
			return s.switchTab(tabGlobalObjects)
		case "7":
			return s.switchTab(tabAuthorizations)
		case "tab", "right", "l":
			return s.switchTab((s.tab + 1) % productTab(len(productTabLabels)))
		case "shift+tab", "left", "h":
			next := s.tab - 1
			if next < 0 {
				next = productTab(len(productTabLabels)) - 1
			}
			return s.switchTab(next)
		}
	}
	return s, nil
}

// switchTab moves the active tab and triggers its loader if not yet loaded.
func (s productDetailScreen) switchTab(t productTab) (screen, tea.Cmd) {
	s.tab = t
	return s, s.loadCmdForTab(t)
}

// loadCmdForTab returns the tea.Cmd that loads the data needed for tab t,
// or nil if the data is already loaded or the storage handle is missing.
func (s productDetailScreen) loadCmdForTab(t productTab) tea.Cmd {
	if s.store == nil || s.product == nil {
		return nil
	}
	pid := s.product.ID
	switch t {
	case tabAssets:
		if s.assetsLoaded {
			return nil
		}
		return func() tea.Msg {
			as, err := s.store.ListAssetsByProduct(ensureContext(), pid)
			if err != nil {
				return errMsg{err: err}
			}
			return assetsLoadedMsg{productID: pid, assets: as}
		}
	case tabAssetScopes:
		if s.scopesLoaded {
			return nil
		}
		return func() tea.Msg {
			sc, err := s.store.ListAssetScopesByProduct(ensureContext(), pid)
			if err != nil {
				return errMsg{err: err}
			}
			return assetScopesLoadedMsg{productID: pid, scopes: sc}
		}
	case tabEntitlements:
		if s.entitlementsLoaded {
			return nil
		}
		return func() tea.Msg {
			es, err := s.store.ListEntitlementsByProduct(ensureContext(), pid)
			if err != nil {
				return errMsg{err: err}
			}
			return entitlementsLoadedMsg{productID: pid, entitlements: es}
		}
	case tabServiceAccounts:
		if s.serviceAccountsLoaded {
			return nil
		}
		return func() tea.Msg {
			sas, err := s.store.ListServiceAccountsByProduct(ensureContext(), pid)
			if err != nil {
				return errMsg{err: err}
			}
			return serviceAccountsLoadedMsg{productID: pid, serviceAccounts: sas}
		}
	case tabGlobalObjects:
		if s.globalObjectsLoaded {
			return nil
		}
		return func() tea.Msg {
			pidCopy := pid
			gos, err := s.store.ListGlobalObjectsByProduct(ensureContext(), &pidCopy)
			if err != nil {
				return errMsg{err: err}
			}
			return globalObjectsLoadedMsg{productID: pid, objects: gos}
		}
	case tabAuthorizations:
		// Authorizations summary depends on the entitlements / service-account
		// / global-object lists. Fetch any prerequisites that are missing,
		// then build the summary once everything is in.
		var cmds []tea.Cmd
		if !s.entitlementsLoaded {
			cmds = append(cmds, s.loadCmdForTab(tabEntitlements))
		}
		if !s.serviceAccountsLoaded {
			cmds = append(cmds, s.loadCmdForTab(tabServiceAccounts))
		}
		if !s.globalObjectsLoaded {
			cmds = append(cmds, s.loadCmdForTab(tabGlobalObjects))
		}
		if len(cmds) == 0 && !s.authzLoaded {
			cmds = append(cmds, s.loadAuthzSummaryIfReady())
		}
		if len(cmds) == 0 {
			return nil
		}
		return tea.Batch(cmds...)
	}
	return nil
}

// loadAuthzSummaryIfReady issues the per-parent authorization queries once
// all prerequisite lists have arrived. Returns nil if any list is still pending.
func (s productDetailScreen) loadAuthzSummaryIfReady() tea.Cmd {
	if s.store == nil || s.product == nil {
		return nil
	}
	if !s.entitlementsLoaded || !s.serviceAccountsLoaded || !s.globalObjectsLoaded {
		return nil
	}
	pid := s.product.ID
	ents := append([]*domain.Entitlement(nil), s.entitlements...)
	sas := append([]*domain.ServiceAccount(nil), s.serviceAccounts...)
	gos := append([]*domain.GlobalObject(nil), s.globalObjects...)
	return func() tea.Msg {
		ctx := ensureContext()
		out := authzSummaryLoadedMsg{
			productID: pid,
			entCounts: make(map[string]int, len(ents)),
			saCounts:  make(map[string]int, len(sas)),
			gobCounts: make(map[string]int, len(gos)),
		}
		for _, e := range ents {
			as, err := s.store.ListAuthorizationsByParent(ctx, domain.AuthParentEntitlement, e.ID)
			if err != nil {
				return errMsg{err: err}
			}
			out.entCounts[e.Name] = len(as)
			out.totalEnt += len(as)
		}
		for _, sa := range sas {
			as, err := s.store.ListAuthorizationsByParent(ctx, domain.AuthParentServiceAccount, sa.ID)
			if err != nil {
				return errMsg{err: err}
			}
			out.saCounts[sa.Name] = len(as)
			out.totalSA += len(as)
		}
		for _, g := range gos {
			as, err := s.store.ListAuthorizationsByParent(ctx, domain.AuthParentGlobalObject, g.ID)
			if err != nil {
				return errMsg{err: err}
			}
			out.gobCounts[g.Name] = len(as)
			out.totalGOB += len(as)
		}
		return out
	}
}

func (s productDetailScreen) View() string {
	if s.product == nil {
		return errorStyle.Render("no product selected")
	}
	var b strings.Builder
	b.WriteString(s.renderTabStrip())
	b.WriteString("\n\n")
	if s.store == nil && s.tab != tabOverview {
		b.WriteString(errorStyle.Render("no database connected"))
		return b.String()
	}
	switch s.tab {
	case tabOverview:
		b.WriteString(s.viewOverview())
	case tabAssets:
		b.WriteString(s.viewAssets())
	case tabAssetScopes:
		b.WriteString(s.viewAssetScopes())
	case tabEntitlements:
		b.WriteString(s.viewEntitlements())
	case tabServiceAccounts:
		b.WriteString(s.viewServiceAccounts())
	case tabGlobalObjects:
		b.WriteString(s.viewGlobalObjects())
	case tabAuthorizations:
		b.WriteString(s.viewAuthorizations())
	}
	b.WriteString("\n\n")
	b.WriteString(helpStyle.Render("1-7 to switch tabs; tab/shift+tab to cycle; q/esc to go back"))
	return b.String()
}

func (s productDetailScreen) renderTabStrip() string {
	var parts []string
	for i, label := range productTabLabels {
		text := fmt.Sprintf("%d %s", i+1, label)
		if productTab(i) == s.tab {
			parts = append(parts, tabActiveStyle.Render(text))
		} else {
			parts = append(parts, tabInactiveStyle.Render(text))
		}
	}
	return strings.Join(parts, " ")
}

func (s productDetailScreen) viewOverview() string {
	var b strings.Builder
	b.WriteString(sectionHeaderStyle.Render(s.product.Name))
	b.WriteString("\n\n")
	b.WriteString(fmt.Sprintf("Owner:       %s\n", s.product.Owner))
	desc := s.product.Description
	if desc == "" {
		desc = dimStyle.Render("(no description)")
	}
	b.WriteString(fmt.Sprintf("Description: %s\n", desc))
	b.WriteString(fmt.Sprintf("Created:     %s\n", s.product.CreatedAt.UTC().Format("2006-01-02 15:04:05 UTC")))
	b.WriteString(fmt.Sprintf("Updated:     %s\n", s.product.UpdatedAt.UTC().Format("2006-01-02 15:04:05 UTC")))
	b.WriteString(fmt.Sprintf("ID:          %s", s.product.ID))
	return b.String()
}

func (s productDetailScreen) viewAssets() string {
	var b strings.Builder
	b.WriteString(sectionHeaderStyle.Render("Assets"))
	b.WriteString("\n\n")
	if s.assetsErr != nil {
		b.WriteString(errorStyle.Render("error: " + s.assetsErr.Error()))
		return b.String()
	}
	if !s.assetsLoaded {
		b.WriteString(dimStyle.Render("loading..."))
		return b.String()
	}
	b.WriteString(fmt.Sprintf("Count: %d\n\n", len(s.assets)))
	if len(s.assets) == 0 {
		b.WriteString(dimStyle.Render("(none)"))
		return b.String()
	}
	for i, a := range s.assets {
		if i >= 10 {
			b.WriteString(dimStyle.Render(fmt.Sprintf("... and %d more", len(s.assets)-10)))
			break
		}
		b.WriteString(rowStyle.Render(fmt.Sprintf("- %s  [%s, %s]", a.Name, a.Type, a.Environment)))
		b.WriteString("\n")
	}
	return b.String()
}

func (s productDetailScreen) viewAssetScopes() string {
	var b strings.Builder
	b.WriteString(sectionHeaderStyle.Render("Asset Scopes"))
	b.WriteString("\n\n")
	if s.scopesErr != nil {
		b.WriteString(errorStyle.Render("error: " + s.scopesErr.Error()))
		return b.String()
	}
	if !s.scopesLoaded {
		b.WriteString(dimStyle.Render("loading..."))
		return b.String()
	}
	b.WriteString(fmt.Sprintf("Count: %d\n\n", len(s.scopes)))
	if len(s.scopes) == 0 {
		b.WriteString(dimStyle.Render("(none)"))
		return b.String()
	}
	for i, sc := range s.scopes {
		if i >= 10 {
			b.WriteString(dimStyle.Render(fmt.Sprintf("... and %d more", len(s.scopes)-10)))
			break
		}
		b.WriteString(rowStyle.Render("- " + sc.Name))
		b.WriteString("\n")
	}
	return b.String()
}

func (s productDetailScreen) viewEntitlements() string {
	var b strings.Builder
	b.WriteString(sectionHeaderStyle.Render("Entitlements"))
	b.WriteString("\n\n")
	if s.entitlementsErr != nil {
		b.WriteString(errorStyle.Render("error: " + s.entitlementsErr.Error()))
		return b.String()
	}
	if !s.entitlementsLoaded {
		b.WriteString(dimStyle.Render("loading..."))
		return b.String()
	}
	b.WriteString(fmt.Sprintf("Count: %d\n\n", len(s.entitlements)))
	if len(s.entitlements) == 0 {
		b.WriteString(dimStyle.Render("(none)"))
		return b.String()
	}
	for i, e := range s.entitlements {
		if i >= 10 {
			b.WriteString(dimStyle.Render(fmt.Sprintf("... and %d more", len(s.entitlements)-10)))
			break
		}
		b.WriteString(rowStyle.Render("- " + e.Name))
		b.WriteString("\n")
	}
	return b.String()
}

func (s productDetailScreen) viewServiceAccounts() string {
	var b strings.Builder
	b.WriteString(sectionHeaderStyle.Render("Service Accounts"))
	b.WriteString("\n\n")
	if s.serviceAccountsErr != nil {
		b.WriteString(errorStyle.Render("error: " + s.serviceAccountsErr.Error()))
		return b.String()
	}
	if !s.serviceAccountsLoaded {
		b.WriteString(dimStyle.Render("loading..."))
		return b.String()
	}
	b.WriteString(fmt.Sprintf("Count: %d\n\n", len(s.serviceAccounts)))
	if len(s.serviceAccounts) == 0 {
		b.WriteString(dimStyle.Render("(none)"))
		return b.String()
	}
	for i, sa := range s.serviceAccounts {
		if i >= 10 {
			b.WriteString(dimStyle.Render(fmt.Sprintf("... and %d more", len(s.serviceAccounts)-10)))
			break
		}
		b.WriteString(rowStyle.Render("- " + sa.Name))
		b.WriteString("\n")
	}
	return b.String()
}

func (s productDetailScreen) viewGlobalObjects() string {
	var b strings.Builder
	b.WriteString(sectionHeaderStyle.Render("Global Objects"))
	b.WriteString("\n\n")
	if s.globalObjectsErr != nil {
		b.WriteString(errorStyle.Render("error: " + s.globalObjectsErr.Error()))
		return b.String()
	}
	if !s.globalObjectsLoaded {
		b.WriteString(dimStyle.Render("loading..."))
		return b.String()
	}
	b.WriteString(fmt.Sprintf("Count: %d\n\n", len(s.globalObjects)))
	if len(s.globalObjects) == 0 {
		b.WriteString(dimStyle.Render("(none)"))
		return b.String()
	}
	for i, g := range s.globalObjects {
		if i >= 10 {
			b.WriteString(dimStyle.Render(fmt.Sprintf("... and %d more", len(s.globalObjects)-10)))
			break
		}
		b.WriteString(rowStyle.Render(fmt.Sprintf("- %s  [%s]", g.Name, g.Type)))
		b.WriteString("\n")
	}
	return b.String()
}

func (s productDetailScreen) viewAuthorizations() string {
	var b strings.Builder
	b.WriteString(sectionHeaderStyle.Render("Authorizations"))
	b.WriteString("\n\n")
	if s.authzErr != nil {
		b.WriteString(errorStyle.Render("error: " + s.authzErr.Error()))
		return b.String()
	}
	if !s.entitlementsLoaded || !s.serviceAccountsLoaded || !s.globalObjectsLoaded || !s.authzLoaded {
		b.WriteString(dimStyle.Render("loading..."))
		return b.String()
	}
	b.WriteString(fmt.Sprintf("By Entitlement     (total %d)\n", s.authzSumm.totalEnt))
	writeCountMap(&b, s.authzSumm.entCounts)
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("By Service Account (total %d)\n", s.authzSumm.totalSA))
	writeCountMap(&b, s.authzSumm.saCounts)
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("By Global Object   (total %d)\n", s.authzSumm.totalGOB))
	writeCountMap(&b, s.authzSumm.gobCounts)
	return b.String()
}

// writeCountMap renders a sorted, indented "name: count" list. Names are
// sorted by the slice they were inserted from, but maps are unordered, so
// we sort here for stable output.
func writeCountMap(b *strings.Builder, m map[string]int) {
	if len(m) == 0 {
		b.WriteString(dimStyle.Render("  (none)"))
		b.WriteString("\n")
		return
	}
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	sortStrings(names)
	for _, n := range names {
		b.WriteString(rowStyle.Render(fmt.Sprintf("  %-30s %d", n, m[n])))
		b.WriteString("\n")
	}
}

// sortStrings is a small wrapper to keep the import surface tight; we only
// need string sort in one place and prefer not to drag in sort across files.
func sortStrings(ss []string) {
	for i := 1; i < len(ss); i++ {
		for j := i; j > 0 && ss[j-1] > ss[j]; j-- {
			ss[j-1], ss[j] = ss[j], ss[j-1]
		}
	}
}
