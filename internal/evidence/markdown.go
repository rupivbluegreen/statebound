package evidence

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// markdownEnvelope is the JSON envelope around a Markdown evidence pack.
// Storing the body inside JSON keeps the on-disk content column always
// parseable as JSON regardless of format.
type markdownEnvelope struct {
	Format string `json:"format"`
	Body   string `json:"body"`
}

// ExportMarkdown renders an auditor-friendly Markdown document derived
// from c, then wraps the rendered text in a JSON envelope and returns
// the envelope's canonical bytes (with trailing newline) for storage.
//
// The render is deterministic given identical PackContent: no timestamps
// are generated at render time, and every collection is iterated in
// stable order (the builder pre-sorts everything).
func ExportMarkdown(c *PackContent) ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("evidence: nil pack content")
	}
	body, err := renderMarkdownBody(c)
	if err != nil {
		return nil, err
	}
	env := markdownEnvelope{
		Format: "markdown",
		Body:   body,
	}
	out, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("evidence: marshal markdown envelope: %w", err)
	}
	out = append(out, '\n')
	return out, nil
}

// renderMarkdownBody produces the human-readable Markdown text. Layout is
// fixed: section order, table column order, and bullet order are all
// deterministic so two renders of the same PackContent yield identical
// strings.
func renderMarkdownBody(c *PackContent) (string, error) {
	var b strings.Builder

	// Header
	fmt.Fprintf(&b, "# Evidence Pack — %s v%d\n\n", c.Product.Name, c.ApprovedVersion.Sequence)

	reason := c.ApprovedVersion.Reason
	if reason == "" {
		reason = "—"
	}
	fmt.Fprintf(&b, "- Generated: %s\n", c.GeneratedAt.UTC().Format(time.RFC3339Nano))
	fmt.Fprintf(&b, "- Approved by: %s (%s)\n", c.ApprovedVersion.ApprovedBy.Subject, c.ApprovedVersion.ApprovedBy.Kind)
	fmt.Fprintf(&b, "- Approved at: %s\n", c.ApprovedVersion.ApprovedAt.UTC().Format(time.RFC3339Nano))
	fmt.Fprintf(&b, "- Approval reason: %s\n", reason)
	fmt.Fprintf(&b, "- Snapshot hash: sha256:%s\n", shortHash(c.ApprovedVersion.SnapshotHash))
	fmt.Fprintf(&b, "- Source change set: %s\n", c.ApprovedVersion.SourceChangeSetID)
	fmt.Fprintf(&b, "- Schema version: %s\n", c.SchemaVersion)
	b.WriteString("\n")

	// Source change set
	b.WriteString("## Source change set\n\n")
	if c.SourceChangeSet != nil {
		cs := c.SourceChangeSet
		fmt.Fprintf(&b, "**%s**\n\n", cs.Title)
		if cs.Description != "" {
			fmt.Fprintf(&b, "%s\n\n", cs.Description)
		}
		fmt.Fprintf(&b, "Requested by %s (%s) at %s; state: %s.\n",
			cs.RequestedBy.Subject, cs.RequestedBy.Kind,
			cs.RequestedAt.UTC().Format(time.RFC3339Nano),
			cs.State)
		if cs.DecidedAt != nil {
			fmt.Fprintf(&b, "\nDecided at %s.\n", cs.DecidedAt.UTC().Format(time.RFC3339Nano))
		}
	} else {
		b.WriteString("_No source change set recorded._\n")
	}
	b.WriteString("\n")

	// Approvals
	b.WriteString("## Approvals\n\n")
	if len(c.Approvals) == 0 {
		b.WriteString("_No approvals recorded._\n\n")
	} else {
		b.WriteString("| Actor | Decision | Reason | Decided at |\n")
		b.WriteString("|-------|----------|--------|------------|\n")
		for _, a := range c.Approvals {
			reason := a.Reason
			if reason == "" {
				reason = "—"
			}
			fmt.Fprintf(&b, "| %s (%s) | %s | %s | %s |\n",
				escapeCell(a.Actor.Subject), a.Actor.Kind,
				a.Decision,
				escapeCell(reason),
				a.DecidedAt.UTC().Format(time.RFC3339Nano))
		}
		b.WriteString("\n")
	}

	// Items
	b.WriteString("## Items\n\n")
	if len(c.Items) == 0 {
		b.WriteString("_No items in this change set._\n\n")
	} else {
		b.WriteString("| Action | Kind | Resource |\n")
		b.WriteString("|--------|------|----------|\n")
		for _, it := range c.Items {
			fmt.Fprintf(&b, "| %s | %s | %s |\n", it.Action, it.Kind, escapeCell(it.ResourceName))
		}
		b.WriteString("\n")
	}

	// Policy decisions
	b.WriteString("## Policy decisions\n\n")
	if len(c.PolicyDecisions) == 0 {
		b.WriteString("_No policy decisions recorded._\n\n")
	} else {
		for _, d := range c.PolicyDecisions {
			fmt.Fprintf(&b, "### %s — %s\n\n", d.Phase, d.Outcome)
			fmt.Fprintf(&b, "- Decision id: %s\n", d.ID)
			fmt.Fprintf(&b, "- Bundle hash: sha256:%s\n", shortHash(d.BundleHash))
			fmt.Fprintf(&b, "- Evaluated at: %s\n\n", d.EvaluatedAt.UTC().Format(time.RFC3339Nano))
			if rendered := renderRulesTable(d.Rules); rendered != "" {
				b.WriteString(rendered)
				b.WriteString("\n")
			}
		}
	}

	// Drift scans (Phase 4'). Skip the section entirely when no scans
	// exist so older evidence packs render unchanged.
	if len(c.DriftScans) > 0 {
		b.WriteString("## Drift scans\n\n")
		for _, scan := range c.DriftScans {
			fmt.Fprintf(&b, "### %s @ %s — %s\n\n",
				scan.ConnectorName,
				scan.StartedAt.UTC().Format(time.RFC3339Nano),
				scan.State,
			)
			fmt.Fprintf(&b, "- Source: %s\n", scan.SourceRef)
			fmt.Fprintf(&b, "- Findings: %d (%s)\n",
				scan.FindingCount,
				renderDriftSeverityCounts(scan.Findings),
			)
			if scan.SummaryHash != "" {
				fmt.Fprintf(&b, "- Summary hash: %s\n", scan.SummaryHash)
			}
			b.WriteString("\n")
			if len(scan.Findings) > 0 {
				b.WriteString("| # | Kind | Severity | Resource | Message |\n")
				b.WriteString("|---|------|----------|----------|---------|\n")
				for _, f := range scan.Findings {
					fmt.Fprintf(&b, "| %d | %s | %s | %s | %s |\n",
						f.Sequence,
						f.Kind,
						f.Severity,
						escapeCell(f.ResourceKind+" "+f.ResourceRef),
						escapeCell(f.Message),
					)
				}
				b.WriteString("\n")
			}
		}
	}

	// Audit events
	b.WriteString("## Audit events\n\n")
	if len(c.AuditEvents) == 0 {
		b.WriteString("_No audit events recorded._\n\n")
	} else {
		b.WriteString("| # | Kind | Actor | Resource | Occurred at | Hash |\n")
		b.WriteString("|---|------|-------|----------|-------------|------|\n")
		for _, e := range c.AuditEvents {
			fmt.Fprintf(&b, "| %d | %s | %s (%s) | %s/%s | %s | %s |\n",
				e.Sequence,
				e.Kind,
				escapeCell(e.Actor.Subject), e.Actor.Kind,
				e.ResourceType, escapeCell(e.ResourceID),
				e.OccurredAt.UTC().Format(time.RFC3339Nano),
				shortHashOrDash(e.Hash))
		}
		b.WriteString("\n")
	}

	// Snapshot
	b.WriteString("## Snapshot\n\n")
	yamlBlock, err := renderSnapshotYAML(c.Snapshot)
	if err != nil {
		return "", err
	}
	b.WriteString("```yaml\n")
	b.WriteString(yamlBlock)
	if !strings.HasSuffix(yamlBlock, "\n") {
		b.WriteString("\n")
	}
	b.WriteString("```\n")

	return b.String(), nil
}

// renderRulesTable renders a canonical-JSON rules array as a Markdown
// table. The shape produced by internal/authz is an array of
// {"name":..., "outcome":..., "message":...} objects but this renderer
// is defensive: missing fields render as "—". Returns the empty string
// if rules is null or not a JSON array.
func renderRulesTable(rules json.RawMessage) string {
	if len(rules) == 0 || string(rules) == "null" {
		return ""
	}
	var arr []map[string]any
	if err := json.Unmarshal(rules, &arr); err != nil {
		return ""
	}
	if len(arr) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("| Rule | Outcome | Message |\n")
	b.WriteString("|------|---------|---------|\n")
	// Sort by name then outcome for stability.
	sort.SliceStable(arr, func(i, j int) bool {
		ni, _ := arr[i]["name"].(string)
		nj, _ := arr[j]["name"].(string)
		if ni != nj {
			return ni < nj
		}
		oi, _ := arr[i]["outcome"].(string)
		oj, _ := arr[j]["outcome"].(string)
		return oi < oj
	})
	for _, r := range arr {
		name := stringField(r, "name")
		outcome := stringField(r, "outcome")
		message := stringField(r, "message")
		fmt.Fprintf(&b, "| %s | %s | %s |\n", escapeCell(name), escapeCell(outcome), escapeCell(message))
	}
	return b.String()
}

// renderSnapshotYAML decodes a canonical-JSON snapshot blob and re-encodes
// it as YAML with sorted map keys. yaml.v3's Marshal of map[string]any
// sorts keys at every level, so the YAML render is deterministic for
// identical input.
func renderSnapshotYAML(raw json.RawMessage) (string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return "{}\n", nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", fmt.Errorf("evidence: decode snapshot for yaml: %w", err)
	}
	v = sortedForYAML(v)
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(v); err != nil {
		return "", fmt.Errorf("evidence: encode snapshot yaml: %w", err)
	}
	if err := enc.Close(); err != nil {
		return "", fmt.Errorf("evidence: close snapshot yaml: %w", err)
	}
	return buf.String(), nil
}

// sortedForYAML walks v and converts every map[string]any into a
// yaml.Node MappingNode whose entries are sorted by key. This guarantees
// the final YAML is byte-identical for identical inputs even if yaml.v3
// changes its default map-iteration behaviour between versions.
func sortedForYAML(v any) any {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		node := &yaml.Node{Kind: yaml.MappingNode}
		for _, k := range keys {
			kn := &yaml.Node{Kind: yaml.ScalarNode, Value: k, Tag: "!!str"}
			vn := &yaml.Node{}
			child := sortedForYAML(t[k])
			if cn, ok := child.(*yaml.Node); ok {
				vn = cn
			} else {
				if err := vn.Encode(child); err != nil {
					// Fall back to raw value rather than panicking; the
					// builder caller will still get a deterministic
					// (if uglier) render.
					vn = &yaml.Node{Kind: yaml.ScalarNode, Value: fmt.Sprintf("%v", child)}
				}
			}
			node.Content = append(node.Content, kn, vn)
		}
		return node
	case []any:
		node := &yaml.Node{Kind: yaml.SequenceNode}
		for _, item := range t {
			child := sortedForYAML(item)
			if cn, ok := child.(*yaml.Node); ok {
				node.Content = append(node.Content, cn)
				continue
			}
			vn := &yaml.Node{}
			if err := vn.Encode(child); err != nil {
				vn = &yaml.Node{Kind: yaml.ScalarNode, Value: fmt.Sprintf("%v", child)}
			}
			node.Content = append(node.Content, vn)
		}
		return node
	default:
		return t
	}
}

// stringField pulls a string field out of a generic map, returning the
// empty string when missing or when the value is not a string.
func stringField(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

// escapeCell escapes pipe characters so a value rendered into a Markdown
// table cell does not split the cell. We also collapse newlines so a
// multi-line description renders as one row.
func escapeCell(s string) string {
	if s == "" {
		return "—"
	}
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

// renderDriftSeverityCounts produces a stable human-readable summary line
// for a drift scan's findings, e.g. "1 critical, 0 high, 2 medium, 0 low,
// 0 info". Severity order is fixed (Critical -> Info) so two renders read
// identically.
func renderDriftSeverityCounts(findings []DriftFindingRef) string {
	counts := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
		"info":     0,
	}
	for _, f := range findings {
		if _, ok := counts[f.Severity]; !ok {
			counts[f.Severity] = 0
		}
		counts[f.Severity]++
	}
	order := []string{"critical", "high", "medium", "low", "info"}
	parts := make([]string, 0, len(order))
	for _, sev := range order {
		parts = append(parts, fmt.Sprintf("%d %s", counts[sev], sev))
	}
	return strings.Join(parts, ", ")
}

// shortHash returns the first 12 hex characters of h, or "—" if h is empty.
func shortHash(h string) string {
	if h == "" {
		return "—"
	}
	if len(h) <= 12 {
		return h
	}
	return h[:12]
}

// shortHashOrDash returns the first 12 hex characters of h, or "—" if h is empty.
func shortHashOrDash(h string) string {
	if h == "" {
		return "—"
	}
	return shortHash(h)
}
