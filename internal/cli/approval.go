package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel/codes"
	"gopkg.in/yaml.v3"

	"statebound.dev/statebound/internal/authz"
	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/model"
	"statebound.dev/statebound/internal/storage"
	"statebound.dev/statebound/internal/telemetry"
)

func addApprovalCmd(parent *cobra.Command) {
	approvalCmd := &cobra.Command{
		Use:   "approval",
		Short: "Manage ChangeSet approvals (request, approve, reject)",
	}
	approvalCmd.AddCommand(
		newApprovalListCmd(),
		newApprovalShowCmd(),
		newApprovalRequestCmd(),
		newApprovalApproveCmd(),
		newApprovalRejectCmd(),
	)
	parent.AddCommand(approvalCmd)
}

// ----- list -----

func newApprovalListCmd() *cobra.Command {
	var (
		productName string
		state       string
		format      string
		limit       int
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List ChangeSets, newest first",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, err := storeFromCmd(cmd)
			if err != nil {
				return err
			}
			defer func() { _ = store.Close(cmd.Context()) }()

			filter := storage.ChangeSetFilter{Limit: limit}
			productNames := map[domain.ID]string{}
			if productName != "" {
				p, err := store.GetProductByName(cmd.Context(), productName)
				if err != nil {
					return fmt.Errorf("lookup product %q: %w", productName, err)
				}
				filter.ProductID = &p.ID
				productNames[p.ID] = p.Name
			}
			if state != "" {
				if !domain.IsValidChangeSetState(state) {
					return fmt.Errorf("unknown state %q", state)
				}
				s := domain.ChangeSetState(state)
				filter.State = &s
			}

			sets, err := store.ListChangeSets(cmd.Context(), filter)
			if err != nil {
				return fmt.Errorf("list change sets: %w", err)
			}
			// Resolve product names for the result rows that aren't already cached.
			for _, cs := range sets {
				if _, ok := productNames[cs.ProductID]; ok {
					continue
				}
				p, err := store.GetProductByID(cmd.Context(), cs.ProductID)
				if err != nil {
					productNames[cs.ProductID] = string(cs.ProductID)
					continue
				}
				productNames[cs.ProductID] = p.Name
			}
			return renderChangeSets(cmd.OutOrStdout(), sets, productNames, format)
		},
	}
	cmd.Flags().StringVar(&productName, "product", "", "filter by product name")
	cmd.Flags().StringVar(&state, "state", "", "filter by state: draft|submitted|approved|rejected|conflicted")
	cmd.Flags().StringVar(&format, "format", "table", "output format: table, json, or yaml")
	cmd.Flags().IntVar(&limit, "limit", 0, "max rows to return; 0 = no limit")
	return cmd
}

// changeSetView is a serializable projection so JSON/YAML output stays stable
// when the domain type grows. Times are RFC3339 UTC strings.
type changeSetView struct {
	ID            string  `json:"id" yaml:"id"`
	Product       string  `json:"product" yaml:"product"`
	State         string  `json:"state" yaml:"state"`
	Title         string  `json:"title" yaml:"title"`
	Description   string  `json:"description,omitempty" yaml:"description,omitempty"`
	RequestedBy   string  `json:"requestedBy" yaml:"requestedBy"`
	ParentVersion *string `json:"parentVersionId,omitempty" yaml:"parentVersionId,omitempty"`
	SubmittedAt   string  `json:"submittedAt,omitempty" yaml:"submittedAt,omitempty"`
	DecidedAt     string  `json:"decidedAt,omitempty" yaml:"decidedAt,omitempty"`
	Decision      string  `json:"decisionReason,omitempty" yaml:"decisionReason,omitempty"`
	CreatedAt     string  `json:"createdAt" yaml:"createdAt"`
	UpdatedAt     string  `json:"updatedAt" yaml:"updatedAt"`
}

func toChangeSetView(cs *domain.ChangeSet, productName string) changeSetView {
	v := changeSetView{
		ID:          string(cs.ID),
		Product:     productName,
		State:       string(cs.State),
		Title:       cs.Title,
		Description: cs.Description,
		RequestedBy: actorString(cs.RequestedBy),
		Decision:    cs.DecisionReason,
		CreatedAt:   cs.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:   cs.UpdatedAt.UTC().Format(time.RFC3339),
	}
	if cs.ParentApprovedVersionID != nil {
		s := string(*cs.ParentApprovedVersionID)
		v.ParentVersion = &s
	}
	if cs.SubmittedAt != nil {
		v.SubmittedAt = cs.SubmittedAt.UTC().Format(time.RFC3339)
	}
	if cs.DecidedAt != nil {
		v.DecidedAt = cs.DecidedAt.UTC().Format(time.RFC3339)
	}
	return v
}

func renderChangeSets(w io.Writer, sets []*domain.ChangeSet, productNames map[domain.ID]string, format string) error {
	switch format {
	case "", "table":
		return renderChangeSetsTable(w, sets, productNames)
	case "json":
		views := make([]changeSetView, 0, len(sets))
		for _, cs := range sets {
			views = append(views, toChangeSetView(cs, productNames[cs.ProductID]))
		}
		b, err := json.MarshalIndent(views, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(w, string(b))
		return err
	case "yaml":
		views := make([]changeSetView, 0, len(sets))
		for _, cs := range sets {
			views = append(views, toChangeSetView(cs, productNames[cs.ProductID]))
		}
		b, err := yaml.Marshal(views)
		if err != nil {
			return err
		}
		_, err = fmt.Fprint(w, string(b))
		return err
	default:
		return fmt.Errorf("unknown format %q (want table, json, or yaml)", format)
	}
}

func renderChangeSetsTable(w io.Writer, sets []*domain.ChangeSet, productNames map[domain.ID]string) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "ID\tSTATE\tPRODUCT\tTITLE\tREQUESTED_BY\tCREATED"); err != nil {
		return err
	}
	for _, cs := range sets {
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			shortID(cs.ID),
			cs.State,
			productNames[cs.ProductID],
			cs.Title,
			actorString(cs.RequestedBy),
			cs.CreatedAt.UTC().Format(time.RFC3339),
		); err != nil {
			return err
		}
	}
	return tw.Flush()
}

// ----- show -----

func newApprovalShowCmd() *cobra.Command {
	var verbose bool
	cmd := &cobra.Command{
		Use:   "show <change-set-id>",
		Short: "Show full ChangeSet detail with grouped items",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storeFromCmd(cmd)
			if err != nil {
				return err
			}
			defer func() { _ = store.Close(cmd.Context()) }()

			csID := domain.ID(args[0])
			cs, err := store.GetChangeSetByID(cmd.Context(), csID)
			if err != nil {
				return fmt.Errorf("get change set: %w", err)
			}
			items, err := store.ListChangeSetItems(cmd.Context(), csID)
			if err != nil {
				return fmt.Errorf("list change set items: %w", err)
			}
			productName := ""
			if p, err := store.GetProductByID(cmd.Context(), cs.ProductID); err == nil {
				productName = p.Name
			}
			return renderChangeSetDetail(cmd.OutOrStdout(), cs, items, productName, verbose)
		},
	}
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "include before/after YAML for each item")
	return cmd
}

// itemKindOrder is the canonical order used by the diff engine. We render the
// detail view in the same order so two `show` runs produce stable output.
var itemKindOrder = []domain.ChangeSetItemKind{
	domain.ChangeSetItemKindProduct,
	domain.ChangeSetItemKindAsset,
	domain.ChangeSetItemKindAssetScope,
	domain.ChangeSetItemKindGlobalObject,
	domain.ChangeSetItemKindEntitlement,
	domain.ChangeSetItemKindServiceAccount,
	domain.ChangeSetItemKindAuthorization,
}

func renderChangeSetDetail(w io.Writer, cs *domain.ChangeSet, items []*domain.ChangeSetItem, productName string, verbose bool) error {
	fmt.Fprintf(w, "ID:           %s\n", cs.ID)
	fmt.Fprintf(w, "State:        %s\n", cs.State)
	fmt.Fprintf(w, "Product:      %s\n", productName)
	fmt.Fprintf(w, "Title:        %s\n", cs.Title)
	if cs.Description != "" {
		fmt.Fprintf(w, "Description:  %s\n", cs.Description)
	}
	fmt.Fprintf(w, "Requested by: %s\n", actorString(cs.RequestedBy))
	if cs.ParentApprovedVersionID != nil {
		fmt.Fprintf(w, "Parent ver:   %s\n", *cs.ParentApprovedVersionID)
	}
	fmt.Fprintf(w, "Created:      %s\n", cs.CreatedAt.UTC().Format(time.RFC3339))
	if cs.SubmittedAt != nil {
		fmt.Fprintf(w, "Submitted:    %s\n", cs.SubmittedAt.UTC().Format(time.RFC3339))
	}
	if cs.DecidedAt != nil {
		fmt.Fprintf(w, "Decided:      %s\n", cs.DecidedAt.UTC().Format(time.RFC3339))
	}
	if cs.DecisionReason != "" {
		fmt.Fprintf(w, "Reason:       %s\n", cs.DecisionReason)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Items (%d):\n", len(items))

	grouped := groupItemsByKind(items)
	for _, kind := range itemKindOrder {
		bucket := grouped[kind]
		if len(bucket) == 0 {
			continue
		}
		fmt.Fprintf(w, "\n  [%s]\n", kind)
		for _, it := range bucket {
			fmt.Fprintf(w, "    %s %s %s\n", it.Action, it.Kind, it.ResourceName)
			if verbose {
				if err := writeItemDiff(w, it); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// groupItemsByKind buckets items by Kind and sorts each bucket by ResourceName
// so the printed order matches the diff engine.
func groupItemsByKind(items []*domain.ChangeSetItem) map[domain.ChangeSetItemKind][]*domain.ChangeSetItem {
	out := map[domain.ChangeSetItemKind][]*domain.ChangeSetItem{}
	for _, it := range items {
		out[it.Kind] = append(out[it.Kind], it)
	}
	for k := range out {
		sort.Slice(out[k], func(i, j int) bool { return out[k][i].ResourceName < out[k][j].ResourceName })
	}
	return out
}

// writeItemDiff renders the before/after payloads as indented YAML blocks.
// Empty payloads are skipped so Adds and Deletes only show one side.
func writeItemDiff(w io.Writer, it *domain.ChangeSetItem) error {
	if it.Before != nil {
		fmt.Fprintln(w, "      before:")
		if err := writeIndentedYAML(w, it.Before, "        "); err != nil {
			return err
		}
	}
	if it.After != nil {
		fmt.Fprintln(w, "      after:")
		if err := writeIndentedYAML(w, it.After, "        "); err != nil {
			return err
		}
	}
	return nil
}

func writeIndentedYAML(w io.Writer, v any, prefix string) error {
	b, err := yaml.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal yaml: %w", err)
	}
	for _, line := range splitLines(string(b)) {
		if line == "" {
			continue
		}
		if _, err := fmt.Fprintln(w, prefix+line); err != nil {
			return err
		}
	}
	return nil
}

// splitLines splits on '\n' without retaining trailing empties, the same way
// strings.Split would but without an extra import for one helper.
func splitLines(s string) []string {
	out := []string{}
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// ----- request -----

func newApprovalRequestCmd() *cobra.Command {
	var csIDStr string
	cmd := &cobra.Command{
		Use:   "request",
		Short: "Submit a draft ChangeSet for review (Draft -> Submitted)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if csIDStr == "" {
				return fmt.Errorf("--change-set is required")
			}
			store, err := storeFromCmd(cmd)
			if err != nil {
				return err
			}
			defer func() { _ = store.Close(cmd.Context()) }()

			actor := actorFromCmd(cmd)
			csID := domain.ID(csIDStr)

			if err := requireCapability(cmd.Context(), store, cmd.ErrOrStderr(), actor, domain.CapabilityChangeSetSubmit); err != nil {
				return err
			}

			cs, err := store.GetChangeSetByID(cmd.Context(), csID)
			if err != nil {
				return fmt.Errorf("get change set: %w", err)
			}
			if cs.State != domain.ChangeSetStateDraft {
				return fmt.Errorf("change set %s is %s, not draft", shortID(csID), cs.State)
			}

			if err := submitChangeSet(cmd.Context(), store, cmd.OutOrStdout(), csID, actor); err != nil {
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&csIDStr, "change-set", "", "id of the draft ChangeSet to submit (required)")
	_ = cmd.MarkFlagRequired("change-set")
	return cmd
}

// ----- approve -----

func newApprovalApproveCmd() *cobra.Command {
	var reason string
	cmd := &cobra.Command{
		Use:   "approve <change-set-id>",
		Short: "Approve a submitted ChangeSet (four-eyes; requester cannot approve)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storeFromCmd(cmd)
			if err != nil {
				return err
			}
			defer func() { _ = store.Close(cmd.Context()) }()

			actor := actorFromCmd(cmd)
			csID := domain.ID(args[0])
			return runApprove(cmd.Context(), store, cmd.OutOrStdout(), csID, actor, reason)
		},
	}
	cmd.Flags().StringVar(&reason, "reason", "", "free-form decision reason")
	return cmd
}

// runApprove drives the Submitted -> Approved transition end-to-end. It is
// extracted from the cobra RunE so the four-eyes test can exercise it against
// an in-memory storage stub.
//
// Wave A telemetry: one "approval.approve" span per call, with the
// change_set_id set up front and product/sequence attributes added
// once they resolve. Errors are recorded on the span before being
// returned so the trace tells the operator why the approval failed.
func runApprove(ctx context.Context, store storage.Storage, w io.Writer, csID domain.ID, actor domain.Actor, reason string) error {
	ctx, span := telemetry.StartSpan(ctx, "approval.approve",
		telemetry.AttrChangeSetID.String(string(csID)),
	)
	defer span.End()
	if telemetry.IncludeActor() {
		span.SetAttributes(
			telemetry.AttrActorKind.String(string(actor.Kind)),
			telemetry.AttrActorSubject.String(actor.Subject),
		)
	}
	recordErr := func(err error) error {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	// Phase 8 wave A: RBAC pre-check runs before any other gate so the
	// audit log captures denials with an authoritative payload before we
	// touch the change set.
	if err := requireCapability(ctx, store, nil, actor, domain.CapabilityApprove); err != nil {
		return recordErr(err)
	}
	cs, err := store.GetChangeSetByID(ctx, csID)
	if err != nil {
		return recordErr(fmt.Errorf("get change set: %w", err))
	}
	span.SetAttributes(telemetry.AttrProductID.String(string(cs.ProductID)))
	if cs.State != domain.ChangeSetStateSubmitted {
		return recordErr(fmt.Errorf("change set %s is %s, not submitted", shortID(csID), cs.State))
	}
	// Four-eyes: the actor performing the approval must differ from the
	// actor who requested the change. Compare both Kind and Subject so a
	// human and a service account with the same subject can't slip past.
	if cs.RequestedBy.Kind == actor.Kind && cs.RequestedBy.Subject == actor.Subject {
		return recordErr(fmt.Errorf("requester cannot approve their own change set; %s=%s", envActor, actor.Subject))
	}

	productName := ""
	if p, err := store.GetProductByID(ctx, cs.ProductID); err == nil {
		productName = p.Name
	}

	var sequence int64
	err = store.WithTx(ctx, func(tx storage.Storage) error {
		// Re-read inside the tx and re-check state to catch a sibling that
		// already moved the change set to Approved/Rejected/Conflicted.
		cur, err := tx.GetChangeSetByID(ctx, csID)
		if err != nil {
			return fmt.Errorf("get change set in tx: %w", err)
		}
		if cur.State != domain.ChangeSetStateSubmitted {
			return fmt.Errorf("change set %s is %s, not submitted", shortID(csID), cur.State)
		}

		result, err := evaluatePolicyGate(ctx, tx, authz.PhaseApprove, cur, actor)
		if err != nil {
			return err
		}
		if err := enforcePolicy(result); err != nil {
			return err
		}

		// Materialize the new approved-version content from the parent
		// snapshot plus this change set's items.
		beforeContent, err := loadParentSnapshotContent(ctx, tx, cur.ProductID)
		if err != nil {
			return err
		}
		items, err := tx.ListChangeSetItems(ctx, csID)
		if err != nil {
			return fmt.Errorf("list change set items: %w", err)
		}
		afterContent, err := applyChangeSetItemsToContent(beforeContent, items)
		if err != nil {
			return fmt.Errorf("apply items to content: %w", err)
		}

		seq, err := tx.NextSequenceForProduct(ctx, cur.ProductID)
		if err != nil {
			return fmt.Errorf("next sequence: %w", err)
		}
		sequence = seq

		snap, err := domain.NewApprovedVersionSnapshot(afterContent)
		if err != nil {
			return fmt.Errorf("build snapshot: %w", err)
		}
		av, err := domain.NewApprovedVersion(cur.ProductID, snap.ID, seq, cur.ParentApprovedVersionID, csID, actor, reason)
		if err != nil {
			return fmt.Errorf("build approved version: %w", err)
		}
		if err := tx.CreateApprovedVersion(ctx, av, snap); err != nil {
			return fmt.Errorf("create approved version: %w", err)
		}

		approval, err := domain.NewApproval(csID, actor, domain.ApprovalDecisionApproved, reason)
		if err != nil {
			return fmt.Errorf("build approval: %w", err)
		}
		if err := tx.CreateApproval(ctx, approval); err != nil {
			return fmt.Errorf("create approval: %w", err)
		}
		if err := emitAuditEvent(ctx, tx, domain.EventApprovalRecorded, actor, "approval", string(approval.ID), map[string]any{
			"change_set_id": string(csID),
			"decision":      string(approval.Decision),
			"reason":        reason,
		}); err != nil {
			return err
		}
		if err := emitAuditEvent(ctx, tx, domain.EventApprovedVersionCreated, actor, "approved_version", string(av.ID), map[string]any{
			"approved_version_id": string(av.ID),
			"product_id":          string(av.ProductID),
			"sequence":            av.Sequence,
			"snapshot_id":         string(av.SnapshotID),
			"source_change_set":   string(csID),
		}); err != nil {
			return err
		}

		now := time.Now().UTC()
		if err := tx.UpdateChangeSetState(ctx, csID, domain.ChangeSetStateApproved, &now, reason); err != nil {
			return fmt.Errorf("transition to approved: %w", err)
		}
		if err := emitAuditEvent(ctx, tx, domain.EventChangeSetApproved, actor, "change_set", string(csID), map[string]any{
			"change_set_id":       string(csID),
			"approved_version_id": string(av.ID),
			"sequence":            av.Sequence,
			"reason":              reason,
		}); err != nil {
			return err
		}

		// Mark every other still-Submitted change set on the same product as
		// Conflicted: their ParentApprovedVersionID no longer matches the
		// product's tip, so reviewers must re-base.
		submitted := domain.ChangeSetStateSubmitted
		others, err := tx.ListChangeSets(ctx, storage.ChangeSetFilter{
			ProductID: &cur.ProductID,
			State:     &submitted,
		})
		if err != nil {
			return fmt.Errorf("list sibling change sets: %w", err)
		}
		for _, sib := range others {
			if sib.ID == csID {
				continue
			}
			conflictReason := fmt.Sprintf("superseded by approved change set %s", shortID(csID))
			if err := tx.UpdateChangeSetState(ctx, sib.ID, domain.ChangeSetStateConflicted, &now, conflictReason); err != nil {
				return fmt.Errorf("mark sibling conflicted: %w", err)
			}
			if err := emitAuditEvent(ctx, tx, domain.EventChangeSetConflicted, actor, "change_set", string(sib.ID), map[string]any{
				"change_set_id":       string(sib.ID),
				"superseded_by":       string(csID),
				"approved_version_id": string(av.ID),
				"reason":              conflictReason,
			}); err != nil {
				return err
			}
		}

		// Apply the new snapshot to the live tables. We reuse the model
		// package's diff-sync apply, which is no-op if storage already
		// matches (e.g. the auto-approve path that pre-populates rows).
		applied, err := model.FromSnapshot(snap.Content)
		if err != nil {
			return fmt.Errorf("decode new snapshot: %w", err)
		}
		if _, err := model.Apply(ctx, txPassthrough{Storage: tx}, cur.ProductID, applied, actor); err != nil {
			return fmt.Errorf("apply snapshot: %w", err)
		}
		return nil
	})
	if err != nil {
		return recordErr(err)
	}

	if productName == "" {
		productName = string(cs.ProductID)
	}
	span.SetAttributes(
		telemetry.AttrProductName.String(productName),
		telemetry.AttrApprovedVersion.Int64(sequence),
	)
	if _, err := fmt.Fprintf(w, "approved change set %s; created version %s:v%d; applied to live tables\n",
		shortID(csID), productName, sequence); err != nil {
		return recordErr(err)
	}
	return nil
}

// loadParentSnapshotContent returns the content of the product's latest
// approved-version snapshot, or an empty map when the product has no prior
// approved versions. The returned map is a fresh copy callers may mutate.
func loadParentSnapshotContent(ctx context.Context, tx storage.Storage, productID domain.ID) (map[string]any, error) {
	_, snap, err := tx.GetLatestApprovedVersion(ctx, productID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return map[string]any{}, nil
		}
		return nil, fmt.Errorf("get latest approved version: %w", err)
	}
	return cloneContent(snap.Content), nil
}

// applyChangeSetItemsToContent reconstructs the post-approval content by
// applying each item's after-state on top of the parent content. We round-trip
// through the model package so both sides land in the same canonical shape.
//
// The simplest correct implementation: decode the parent into a model, apply
// item-by-item to the model, re-encode to snapshot content. Since the diff
// engine is generated from the YAML model itself, the easier path is: take
// any item's After payload and merge it into the parent under the same key
// path. But change-set items reference resources by name and have separate
// shapes per kind; rebuilding the model from items is not 1:1.
//
// Instead we use the higher-level fact: the items represent a complete diff
// from `before` to `after`. The simplest reconstruction is to let the
// approving CLI call decode the latest approved snapshot into a model, apply
// each item's intent, and re-encode. For the Phase 2 wave A scope we keep
// this simple: rebuild the model from the parent, then for each item, mutate
// the corresponding section by ResourceName.
func applyChangeSetItemsToContent(beforeContent map[string]any, items []*domain.ChangeSetItem) (map[string]any, error) {
	// Decode parent snapshot (or an empty model if there is no parent).
	var current *model.ProductAuthorizationModel
	if len(beforeContent) == 0 {
		current = &model.ProductAuthorizationModel{}
	} else {
		m, err := model.FromSnapshot(beforeContent)
		if err != nil {
			return nil, fmt.Errorf("decode parent snapshot: %w", err)
		}
		current = m
	}

	for _, it := range items {
		if err := applyItemToModel(current, it); err != nil {
			return nil, fmt.Errorf("apply item %s/%s: %w", it.Kind, it.ResourceName, err)
		}
	}

	// Ensure header invariants are present for the YAML round-trip.
	if current.APIVersion == "" {
		current.APIVersion = model.APIVersion
	}
	if current.Kind == "" {
		current.Kind = model.Kind
	}
	return model.ToSnapshotContent(current)
}

// applyItemToModel mutates `m` in-place to reflect a single ChangeSetItem.
// Resource names follow the same scheme used by the diff engine:
//   - "product:<name>"
//   - "asset:<name>", "asset_scope:<name>", "global_object:<name>"
//   - "entitlement:<name>", "service_account:<name>"
//   - "authorization:<parent_kind>:<parent_name>:<index>"
//
// On Add/Update we decode the `After` payload into the matching YAML struct;
// on Delete we drop the matching entry.
func applyItemToModel(m *model.ProductAuthorizationModel, it *domain.ChangeSetItem) error {
	switch it.Kind {
	case domain.ChangeSetItemKindProduct:
		return applyProductItem(m, it)
	case domain.ChangeSetItemKindAsset:
		return applyAssetItem(m, it)
	case domain.ChangeSetItemKindAssetScope:
		return applyAssetScopeItem(m, it)
	case domain.ChangeSetItemKindGlobalObject:
		return applyGlobalObjectItem(m, it)
	case domain.ChangeSetItemKindEntitlement:
		return applyEntitlementItem(m, it)
	case domain.ChangeSetItemKindServiceAccount:
		return applyServiceAccountItem(m, it)
	case domain.ChangeSetItemKindAuthorization:
		return applyAuthorizationItem(m, it)
	}
	return fmt.Errorf("unknown item kind %q", it.Kind)
}

func applyProductItem(m *model.ProductAuthorizationModel, it *domain.ChangeSetItem) error {
	if it.Action == domain.ChangeSetActionDelete {
		// Product deletes don't appear in single-import flows; clear metadata to be safe.
		m.Metadata = model.ProductMetadata{}
		return nil
	}
	var meta model.ProductMetadata
	if err := decodeYAMLMap(it.After, &meta); err != nil {
		return err
	}
	m.Metadata = meta
	return nil
}

func applyAssetItem(m *model.ProductAuthorizationModel, it *domain.ChangeSetItem) error {
	name := stripPrefix(it.ResourceName, "asset:")
	if it.Action == domain.ChangeSetActionDelete {
		m.Spec.Assets = removeNamed(m.Spec.Assets, func(a model.YAMLAsset) string { return a.Name }, name)
		return nil
	}
	var asset model.YAMLAsset
	if err := decodeYAMLMap(it.After, &asset); err != nil {
		return err
	}
	m.Spec.Assets = upsertNamed(m.Spec.Assets, func(a model.YAMLAsset) string { return a.Name }, name, asset)
	return nil
}

func applyAssetScopeItem(m *model.ProductAuthorizationModel, it *domain.ChangeSetItem) error {
	name := stripPrefix(it.ResourceName, "asset_scope:")
	if it.Action == domain.ChangeSetActionDelete {
		m.Spec.AssetScopes = removeNamed(m.Spec.AssetScopes, func(s model.YAMLAssetScope) string { return s.Name }, name)
		return nil
	}
	var scope model.YAMLAssetScope
	if err := decodeYAMLMap(it.After, &scope); err != nil {
		return err
	}
	m.Spec.AssetScopes = upsertNamed(m.Spec.AssetScopes, func(s model.YAMLAssetScope) string { return s.Name }, name, scope)
	return nil
}

func applyGlobalObjectItem(m *model.ProductAuthorizationModel, it *domain.ChangeSetItem) error {
	name := stripPrefix(it.ResourceName, "global_object:")
	if it.Action == domain.ChangeSetActionDelete {
		m.Spec.GlobalObjects = removeNamed(m.Spec.GlobalObjects, func(g model.YAMLGlobalObject) string { return g.Name }, name)
		return nil
	}
	var obj model.YAMLGlobalObject
	if err := decodeYAMLMap(it.After, &obj); err != nil {
		return err
	}
	m.Spec.GlobalObjects = upsertNamed(m.Spec.GlobalObjects, func(g model.YAMLGlobalObject) string { return g.Name }, name, obj)
	return nil
}

func applyEntitlementItem(m *model.ProductAuthorizationModel, it *domain.ChangeSetItem) error {
	name := stripPrefix(it.ResourceName, "entitlement:")
	if it.Action == domain.ChangeSetActionDelete {
		m.Spec.Entitlements = removeNamed(m.Spec.Entitlements, func(e model.YAMLEntitlement) string { return e.Name }, name)
		return nil
	}
	// The diff engine stores only the header (name, owner, purpose) under
	// the entitlement item. Inline authorizations diff as separate items.
	// We preserve the existing authorization list when we update the header.
	var header model.YAMLEntitlement
	if err := decodeYAMLMap(it.After, &header); err != nil {
		return err
	}
	for i := range m.Spec.Entitlements {
		if m.Spec.Entitlements[i].Name == name {
			header.Authorizations = m.Spec.Entitlements[i].Authorizations
			m.Spec.Entitlements[i] = header
			return nil
		}
	}
	m.Spec.Entitlements = append(m.Spec.Entitlements, header)
	return nil
}

func applyServiceAccountItem(m *model.ProductAuthorizationModel, it *domain.ChangeSetItem) error {
	name := stripPrefix(it.ResourceName, "service_account:")
	if it.Action == domain.ChangeSetActionDelete {
		m.Spec.ServiceAccounts = removeNamed(m.Spec.ServiceAccounts, func(s model.YAMLServiceAccount) string { return s.Name }, name)
		return nil
	}
	var header model.YAMLServiceAccount
	if err := decodeYAMLMap(it.After, &header); err != nil {
		return err
	}
	for i := range m.Spec.ServiceAccounts {
		if m.Spec.ServiceAccounts[i].Name == name {
			header.Authorizations = m.Spec.ServiceAccounts[i].Authorizations
			m.Spec.ServiceAccounts[i] = header
			return nil
		}
	}
	m.Spec.ServiceAccounts = append(m.Spec.ServiceAccounts, header)
	return nil
}

// applyAuthorizationItem handles "authorization:<parent_kind>:<parent_name>:<index>".
func applyAuthorizationItem(m *model.ProductAuthorizationModel, it *domain.ChangeSetItem) error {
	parentKind, parentName, index, err := parseAuthorizationResource(it.ResourceName)
	if err != nil {
		return err
	}

	switch parentKind {
	case "entitlement":
		for i := range m.Spec.Entitlements {
			if m.Spec.Entitlements[i].Name != parentName {
				continue
			}
			auths, err := mutateAuthorizations(m.Spec.Entitlements[i].Authorizations, index, it)
			if err != nil {
				return err
			}
			m.Spec.Entitlements[i].Authorizations = auths
			return nil
		}
		return fmt.Errorf("entitlement %q not found for authorization", parentName)
	case "service_account":
		for i := range m.Spec.ServiceAccounts {
			if m.Spec.ServiceAccounts[i].Name != parentName {
				continue
			}
			auths, err := mutateAuthorizations(m.Spec.ServiceAccounts[i].Authorizations, index, it)
			if err != nil {
				return err
			}
			m.Spec.ServiceAccounts[i].Authorizations = auths
			return nil
		}
		return fmt.Errorf("service_account %q not found for authorization", parentName)
	}
	return fmt.Errorf("unknown authorization parent kind %q", parentKind)
}

// mutateAuthorizations applies one Add/Update/Delete to a parent's
// authorization list at the given index. Adds beyond the current length pad
// the slice with empties; deletes within range remove the entry.
func mutateAuthorizations(current []model.YAMLAuthorization, index int, it *domain.ChangeSetItem) ([]model.YAMLAuthorization, error) {
	if it.Action == domain.ChangeSetActionDelete {
		if index < 0 || index >= len(current) {
			return current, nil
		}
		out := make([]model.YAMLAuthorization, 0, len(current)-1)
		out = append(out, current[:index]...)
		out = append(out, current[index+1:]...)
		return out, nil
	}
	var auth model.YAMLAuthorization
	if err := decodeYAMLMap(it.After, &auth); err != nil {
		return nil, err
	}
	if index == len(current) {
		return append(current, auth), nil
	}
	if index >= 0 && index < len(current) {
		current[index] = auth
		return current, nil
	}
	// Pad if a non-contiguous index is requested. Defensive; the diff engine
	// emits dense indices so this branch should not normally fire.
	for len(current) < index {
		current = append(current, model.YAMLAuthorization{})
	}
	return append(current, auth), nil
}

func parseAuthorizationResource(s string) (parentKind, parentName string, index int, err error) {
	const prefix = "authorization:"
	if !hasPrefix(s, prefix) {
		return "", "", 0, fmt.Errorf("malformed authorization resource %q", s)
	}
	rest := s[len(prefix):]
	first := indexOf(rest, ':')
	if first < 0 {
		return "", "", 0, fmt.Errorf("malformed authorization resource %q", s)
	}
	parentKind = rest[:first]
	rest = rest[first+1:]
	last := lastIndexOf(rest, ':')
	if last < 0 {
		return "", "", 0, fmt.Errorf("malformed authorization resource %q", s)
	}
	parentName = rest[:last]
	idxStr := rest[last+1:]
	idx, perr := parseInt(idxStr)
	if perr != nil {
		return "", "", 0, fmt.Errorf("malformed authorization index in %q: %w", s, perr)
	}
	return parentKind, parentName, idx, nil
}

// ----- reject -----

func newApprovalRejectCmd() *cobra.Command {
	var reason string
	cmd := &cobra.Command{
		Use:   "reject <change-set-id>",
		Short: "Reject a submitted ChangeSet (reason required)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if reason == "" {
				return fmt.Errorf("--reason is required when rejecting")
			}
			store, err := storeFromCmd(cmd)
			if err != nil {
				return err
			}
			defer func() { _ = store.Close(cmd.Context()) }()

			actor := actorFromCmd(cmd)
			csID := domain.ID(args[0])

			if err := requireCapability(cmd.Context(), store, cmd.ErrOrStderr(), actor, domain.CapabilityReject); err != nil {
				return err
			}

			cs, err := store.GetChangeSetByID(cmd.Context(), csID)
			if err != nil {
				return fmt.Errorf("get change set: %w", err)
			}
			if cs.State != domain.ChangeSetStateSubmitted {
				return fmt.Errorf("change set %s is %s, not submitted", shortID(csID), cs.State)
			}

			if err := store.WithTx(cmd.Context(), func(tx storage.Storage) error {
				now := time.Now().UTC()
				if err := tx.UpdateChangeSetState(cmd.Context(), csID, domain.ChangeSetStateRejected, &now, reason); err != nil {
					return fmt.Errorf("transition to rejected: %w", err)
				}
				approval, err := domain.NewApproval(csID, actor, domain.ApprovalDecisionRejected, reason)
				if err != nil {
					return fmt.Errorf("build approval: %w", err)
				}
				if err := tx.CreateApproval(cmd.Context(), approval); err != nil {
					return fmt.Errorf("create approval: %w", err)
				}
				if err := emitAuditEvent(cmd.Context(), tx, domain.EventApprovalRecorded, actor, "approval", string(approval.ID), map[string]any{
					"change_set_id": string(csID),
					"decision":      string(approval.Decision),
					"reason":        reason,
				}); err != nil {
					return err
				}
				if err := emitAuditEvent(cmd.Context(), tx, domain.EventChangeSetRejected, actor, "change_set", string(csID), map[string]any{
					"change_set_id": string(csID),
					"reason":        reason,
				}); err != nil {
					return err
				}
				return nil
			}); err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "rejected change set %s: %s\n", shortID(csID), reason)
			return err
		},
	}
	cmd.Flags().StringVar(&reason, "reason", "", "free-form decision reason (required)")
	_ = cmd.MarkFlagRequired("reason")
	return cmd
}

// ----- shared helpers -----

// emitAuditEvent constructs and persists an audit event in one call. Every
// state-transition handler in this file routes through here so audit payload
// shape stays consistent.
func emitAuditEvent(ctx context.Context, tx storage.Storage, kind domain.EventKind, actor domain.Actor, resourceType, resourceID string, payload map[string]any) error {
	evt, err := domain.NewAuditEvent(kind, actor, resourceType, resourceID, payload)
	if err != nil {
		return fmt.Errorf("build %s audit: %w", kind, err)
	}
	if err := tx.AppendAuditEvent(ctx, evt); err != nil {
		return fmt.Errorf("append %s audit: %w", kind, err)
	}
	return nil
}

// txPassthrough lets us call model.Apply from inside an outer transaction
// without opening a new one. model.Apply calls store.WithTx internally; the
// passthrough makes that call run fn directly against the same handle.
type txPassthrough struct {
	storage.Storage
}

func (t txPassthrough) WithTx(ctx context.Context, fn func(tx storage.Storage) error) error {
	return fn(t.Storage)
}

func actorString(a domain.Actor) string {
	return string(a.Kind) + ":" + a.Subject
}

// decodeYAMLMap round-trips a map[string]any payload through YAML into the
// target type. ChangeSetItem.Before/After payloads are produced by the diff
// engine via the same yaml.Marshal hook, so this matches the source shape.
func decodeYAMLMap(src map[string]any, dst any) error {
	if src == nil {
		return nil
	}
	b, err := yaml.Marshal(src)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}
	if err := yaml.Unmarshal(b, dst); err != nil {
		return fmt.Errorf("unmarshal payload: %w", err)
	}
	return nil
}

// removeNamed returns a copy of src with every entry whose name() == target
// removed. Order is preserved.
func removeNamed[T any](src []T, name func(T) string, target string) []T {
	out := make([]T, 0, len(src))
	for _, v := range src {
		if name(v) == target {
			continue
		}
		out = append(out, v)
	}
	return out
}

// upsertNamed replaces the first entry whose name() == target with v, or
// appends v when no match is found. Order is preserved.
func upsertNamed[T any](src []T, name func(T) string, target string, v T) []T {
	for i := range src {
		if name(src[i]) == target {
			src[i] = v
			return src
		}
	}
	return append(src, v)
}

// cloneContent returns a deep copy of a snapshot content map. We marshal/
// unmarshal through JSON because the content is already pure JSON-native
// after going through ToSnapshotContent.
func cloneContent(in map[string]any) map[string]any {
	if in == nil {
		return map[string]any{}
	}
	b, err := json.Marshal(in)
	if err != nil {
		return map[string]any{}
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return map[string]any{}
	}
	return out
}

// stripPrefix returns s with prefix removed when present, otherwise s.
func stripPrefix(s, prefix string) string {
	if hasPrefix(s, prefix) {
		return s[len(prefix):]
	}
	return s
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func indexOf(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func lastIndexOf(s string, c byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// parseInt parses a non-negative decimal int without depending on strconv to
// keep this file's import surface minimal.
func parseInt(s string) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("empty number")
	}
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid digit %q", c)
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}
