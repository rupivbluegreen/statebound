package tui

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"statebound.dev/statebound/internal/domain"
)

// RenderDiffItems renders a list of ChangeSetItems as a multi-section diff
// block, one section per kind in stable order. Within each kind, items are
// sorted by ResourceName so the output is deterministic.
//
// The width parameter is accepted for forward compatibility (e.g. side-by-side
// layout in a future revision); the current renderer is single-column and
// uses width only to size header rules.
func RenderDiffItems(items []*domain.ChangeSetItem, width int) string {
	if len(items) == 0 {
		return dimStyle.Render("(no items)")
	}
	if width < 20 {
		width = 20
	}

	// Bucket items by kind, then sort each bucket by ResourceName.
	byKind := make(map[domain.ChangeSetItemKind][]*domain.ChangeSetItem)
	for _, it := range items {
		if it == nil {
			continue
		}
		byKind[it.Kind] = append(byKind[it.Kind], it)
	}
	for _, group := range byKind {
		sort.Slice(group, func(i, j int) bool {
			return group[i].ResourceName < group[j].ResourceName
		})
	}

	var b strings.Builder
	for _, kind := range diffKindOrder {
		group, ok := byKind[kind]
		if !ok || len(group) == 0 {
			continue
		}
		b.WriteString(sectionHeaderStyle.Render(string(kind)))
		b.WriteString("\n")
		for _, it := range group {
			b.WriteString(renderDiffItem(it))
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	out := strings.TrimRight(b.String(), "\n")
	return out
}

// diffKindOrder is the stable kind ordering used by RenderDiffItems.
// It matches the natural top-down reading order for an authorization model.
var diffKindOrder = []domain.ChangeSetItemKind{
	domain.ChangeSetItemKindProduct,
	domain.ChangeSetItemKindAsset,
	domain.ChangeSetItemKindAssetScope,
	domain.ChangeSetItemKindEntitlement,
	domain.ChangeSetItemKindServiceAccount,
	domain.ChangeSetItemKindGlobalObject,
	domain.ChangeSetItemKindAuthorization,
}

// renderDiffItem renders a single ChangeSetItem with header line and body.
func renderDiffItem(it *domain.ChangeSetItem) string {
	var b strings.Builder
	switch it.Action {
	case domain.ChangeSetActionAdd:
		header := fmt.Sprintf("+ %s %s", it.Kind, it.ResourceName)
		b.WriteString(addStyle.Render(header))
		b.WriteString("\n")
		body := indentText(yamlOrEmpty(it.After), 4)
		b.WriteString(addStyle.Render(body))
	case domain.ChangeSetActionDelete:
		header := fmt.Sprintf("- %s %s", it.Kind, it.ResourceName)
		b.WriteString(deleteStyle.Render(header))
		b.WriteString("\n")
		body := indentText(yamlOrEmpty(it.Before), 4)
		b.WriteString(deleteStyle.Render(body))
	case domain.ChangeSetActionUpdate:
		header := fmt.Sprintf("~ %s %s", it.Kind, it.ResourceName)
		b.WriteString(updateStyle.Render(header))
		b.WriteString("\n")
		b.WriteString(deleteStyle.Render("    before:"))
		b.WriteString("\n")
		b.WriteString(deleteStyle.Render(indentText(yamlOrEmpty(it.Before), 6)))
		b.WriteString("\n")
		b.WriteString(addStyle.Render("    after:"))
		b.WriteString("\n")
		b.WriteString(addStyle.Render(indentText(yamlOrEmpty(it.After), 6)))
	default:
		// Unknown action — fall back to a neutral header so we never blow up.
		header := fmt.Sprintf("? %s %s", it.Kind, it.ResourceName)
		b.WriteString(dimStyle.Render(header))
	}
	return b.String()
}

// yamlOrEmpty marshals m to YAML, returning a sentinel string when m is nil
// or empty so the rendered diff is never an empty pair of braces.
func yamlOrEmpty(m map[string]any) string {
	if len(m) == 0 {
		return "(empty)"
	}
	out, err := yaml.Marshal(m)
	if err != nil {
		return fmt.Sprintf("(yaml error: %v)", err)
	}
	return strings.TrimRight(string(out), "\n")
}

// indentText prefixes every line of s with n spaces.
func indentText(s string, n int) string {
	if s == "" {
		return ""
	}
	pad := strings.Repeat(" ", n)
	lines := strings.Split(s, "\n")
	for i, ln := range lines {
		lines[i] = pad + ln
	}
	return strings.Join(lines, "\n")
}
