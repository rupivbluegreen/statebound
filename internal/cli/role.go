// Package cli — role subcommand. Phase 8 wave A surfaces the
// actor_role_bindings table to operators so they can grant, list, and
// revoke RBAC bindings from the terminal.
//
// `role grant` and `role revoke` require the calling actor to hold
// rbac:manage (admin role). The bootstrap problem is solved with the
// `--bootstrap` flag on grant: when the actor_role_bindings table has
// no admin row yet, a one-time bootstrap grant is allowed without an
// RBAC pre-check. Any subsequent attempt with `--bootstrap` fails.
package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/storage"
)

// addRoleCmd registers `statebound role` and its subcommands on parent
// (root command).
func addRoleCmd(parent *cobra.Command) {
	cmd := &cobra.Command{
		Use:   "role",
		Short: "Manage operator role bindings (RBAC)",
		Long: "Role grants gate the approval, plan, drift, and apply " +
			"actions. Use `role grant` to add a binding, `role revoke` to " +
			"remove one, and `role list` to inspect the current set. " +
			"Bootstrap the first admin with `role grant --bootstrap`.",
	}
	cmd.AddCommand(newRoleListCmd(), newRoleGrantCmd(), newRoleRevokeCmd())
	parent.AddCommand(cmd)
}

// ----- list -----

func newRoleListCmd() *cobra.Command {
	var (
		actorRef string
		roleStr  string
		active   bool
		format   string
		limit    int
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List actor role bindings",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, err := storeFromCmd(cmd)
			if err != nil {
				return err
			}
			defer func() { _ = store.Close(cmd.Context()) }()

			filter := storage.ActorRoleBindingFilter{
				OnlyActive: active,
				Limit:      limit,
			}
			if actorRef != "" {
				kind, subject, err := parseActorRef(actorRef)
				if err != nil {
					return err
				}
				filter.ActorKind = kind
				filter.ActorSubject = subject
			}
			if roleStr != "" {
				if !domain.IsValidRole(domain.Role(roleStr)) {
					return fmt.Errorf("invalid role %q (want one of %s)", roleStr, allRoleNames())
				}
				filter.Role = domain.Role(roleStr)
			}

			bindings, err := store.ListActorRoleBindings(cmd.Context(), filter)
			if err != nil {
				return fmt.Errorf("list role bindings: %w", err)
			}
			return renderRoleBindings(cmd.OutOrStdout(), bindings, format)
		},
	}
	cmd.Flags().StringVar(&actorRef, "actor", "", "filter by actor kind:subject (e.g. human:alice@example.com)")
	cmd.Flags().StringVar(&roleStr, "role", "", "filter by role: viewer|requester|approver|operator|admin")
	cmd.Flags().BoolVar(&active, "active", false, "include only currently-active bindings (exclude expired)")
	cmd.Flags().StringVar(&format, "format", "table", "output format: table, json, yaml")
	cmd.Flags().IntVar(&limit, "limit", 0, "max rows to return; 0 = no limit")
	return cmd
}

// roleBindingView is the serializable projection so JSON output stays
// stable as the domain type evolves.
type roleBindingView struct {
	ID           string  `json:"id"`
	ActorKind    string  `json:"actor_kind"`
	ActorSubject string  `json:"actor_subject"`
	Role         string  `json:"role"`
	GrantedBy    string  `json:"granted_by"`
	GrantedAt    string  `json:"granted_at"`
	ExpiresAt    *string `json:"expires_at,omitempty"`
	Note         string  `json:"note,omitempty"`
	Active       bool    `json:"active"`
}

func toRoleBindingView(b *domain.ActorRoleBinding, now time.Time) roleBindingView {
	v := roleBindingView{
		ID:           string(b.ID),
		ActorKind:    string(b.Actor.Kind),
		ActorSubject: b.Actor.Subject,
		Role:         string(b.Role),
		GrantedBy:    string(b.GrantedBy.Kind) + ":" + b.GrantedBy.Subject,
		GrantedAt:    b.GrantedAt.UTC().Format(time.RFC3339),
		Note:         b.Note,
		Active:       b.IsActive(now),
	}
	if b.ExpiresAt != nil {
		s := b.ExpiresAt.UTC().Format(time.RFC3339)
		v.ExpiresAt = &s
	}
	return v
}

func renderRoleBindings(w io.Writer, bindings []*domain.ActorRoleBinding, format string) error {
	now := time.Now().UTC()
	switch format {
	case "", "table":
		return renderRoleBindingsTable(w, bindings, now)
	case "json":
		views := make([]roleBindingView, 0, len(bindings))
		for _, b := range bindings {
			views = append(views, toRoleBindingView(b, now))
		}
		b, err := json.MarshalIndent(views, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(w, string(b))
		return err
	default:
		return fmt.Errorf("unknown format %q (want table or json)", format)
	}
}

func renderRoleBindingsTable(w io.Writer, bindings []*domain.ActorRoleBinding, now time.Time) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "ID\tACTOR\tROLE\tGRANTED_BY\tGRANTED_AT\tEXPIRES_AT\tACTIVE\tNOTE"); err != nil {
		return err
	}
	for _, b := range bindings {
		expires := "-"
		if b.ExpiresAt != nil {
			expires = b.ExpiresAt.UTC().Format(time.RFC3339)
		}
		active := "yes"
		if !b.IsActive(now) {
			active = "no"
		}
		if _, err := fmt.Fprintf(tw, "%s\t%s:%s\t%s\t%s:%s\t%s\t%s\t%s\t%s\n",
			shortID(b.ID),
			b.Actor.Kind, b.Actor.Subject,
			b.Role,
			b.GrantedBy.Kind, b.GrantedBy.Subject,
			b.GrantedAt.UTC().Format(time.RFC3339),
			expires,
			active,
			b.Note,
		); err != nil {
			return err
		}
	}
	return tw.Flush()
}

// ----- grant -----

func newRoleGrantCmd() *cobra.Command {
	var (
		actorRef  string
		roleStr   string
		expires   string
		note      string
		bootstrap bool
	)
	cmd := &cobra.Command{
		Use:   "grant",
		Short: "Grant a role to an actor",
		Long: "Creates an actor_role_bindings row binding the named actor " +
			"to the named role. Requires the calling actor to hold the " +
			"admin role (rbac:manage capability), unless --bootstrap is " +
			"passed and no admin binding exists yet.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !domain.IsValidRole(domain.Role(roleStr)) {
				return fmt.Errorf("invalid role %q (want one of %s)", roleStr, allRoleNames())
			}
			kind, subject, err := parseActorRef(actorRef)
			if err != nil {
				return err
			}
			actor := domain.Actor{Kind: domain.ActorKind(kind), Subject: subject}
			if err := actor.Validate(); err != nil {
				return fmt.Errorf("--actor: %w", err)
			}

			var expiresAt *time.Time
			if expires != "" {
				d, err := time.ParseDuration(expires)
				if err != nil {
					return fmt.Errorf("--expires: %w", err)
				}
				t := time.Now().UTC().Add(d)
				expiresAt = &t
			}

			store, err := storeFromCmd(cmd)
			if err != nil {
				return err
			}
			defer func() { _ = store.Close(cmd.Context()) }()

			callingActor := actorFromCmd(cmd)

			if bootstrap {
				existing, err := hasAdminBinding(cmd.Context(), store)
				if err != nil {
					return err
				}
				if existing {
					return fmt.Errorf("--bootstrap refused: an admin binding already exists; revoke it first or run without --bootstrap")
				}
				// Bootstrap path bypasses requireCapability; the
				// authorisation gate is "no admin exists yet".
			} else {
				if err := requireCapability(cmd.Context(), store, cmd.ErrOrStderr(), callingActor, domain.CapabilityRoleManage); err != nil {
					return err
				}
			}

			binding, err := domain.NewActorRoleBinding(actor, domain.Role(roleStr), callingActor, expiresAt, note)
			if err != nil {
				return fmt.Errorf("build binding: %w", err)
			}

			if err := store.WithTx(cmd.Context(), func(tx storage.Storage) error {
				if err := tx.AppendActorRoleBinding(cmd.Context(), binding); err != nil {
					if errors.Is(err, storage.ErrRoleBindingDuplicate) {
						return fmt.Errorf("binding already exists for %s:%s -> %s",
							actor.Kind, actor.Subject, roleStr)
					}
					return fmt.Errorf("append binding: %w", err)
				}
				payload := map[string]any{
					"binding_id":    string(binding.ID),
					"actor_kind":    string(actor.Kind),
					"actor_subject": actor.Subject,
					"role":          string(binding.Role),
					"granted_by":    string(callingActor.Kind) + ":" + callingActor.Subject,
					"note":          note,
					"bootstrap":     bootstrap,
				}
				if expiresAt != nil {
					payload["expires_at"] = expiresAt.UTC().Format(time.RFC3339)
				}
				if err := emitAuditEvent(cmd.Context(), tx, domain.EventRoleBindingGranted, callingActor, "actor_role_binding", string(binding.ID), payload); err != nil {
					return err
				}
				return nil
			}); err != nil {
				return err
			}

			_, err = fmt.Fprintf(cmd.OutOrStdout(),
				"granted role %s to %s:%s (binding %s)\n",
				binding.Role, actor.Kind, actor.Subject, shortID(binding.ID))
			return err
		},
	}
	cmd.Flags().StringVar(&actorRef, "actor", "", "actor as kind:subject (required)")
	cmd.Flags().StringVar(&roleStr, "role", "", "role to grant: viewer|requester|approver|operator|admin (required)")
	cmd.Flags().StringVar(&expires, "expires", "", "optional duration after which the binding expires (e.g. 168h)")
	cmd.Flags().StringVar(&note, "note", "", "optional free-form note recorded on the audit event")
	cmd.Flags().BoolVar(&bootstrap, "bootstrap", false,
		"one-time admin grant: skips the rbac:manage check; refused once any admin binding exists")
	_ = cmd.MarkFlagRequired("actor")
	_ = cmd.MarkFlagRequired("role")
	return cmd
}

// ----- revoke -----

func newRoleRevokeCmd() *cobra.Command {
	var bindingID string
	cmd := &cobra.Command{
		Use:   "revoke",
		Short: "Revoke a role binding by id",
		Long: "Removes an actor_role_bindings row by id. Requires the " +
			"calling actor to hold rbac:manage (admin role).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if bindingID == "" {
				return fmt.Errorf("--binding is required")
			}
			store, err := storeFromCmd(cmd)
			if err != nil {
				return err
			}
			defer func() { _ = store.Close(cmd.Context()) }()

			callingActor := actorFromCmd(cmd)
			if err := requireCapability(cmd.Context(), store, cmd.ErrOrStderr(), callingActor, domain.CapabilityRoleManage); err != nil {
				return err
			}

			id := domain.ID(bindingID)
			// Resolve the binding before deletion so the audit event
			// captures the (actor, role) tuple even after the row is
			// gone.
			bindings, err := store.ListActorRoleBindings(cmd.Context(), storage.ActorRoleBindingFilter{Limit: 0})
			if err != nil {
				return fmt.Errorf("list role bindings: %w", err)
			}
			var matched *domain.ActorRoleBinding
			for _, b := range bindings {
				if b.ID == id {
					matched = b
					break
				}
			}
			if matched == nil {
				return fmt.Errorf("binding %s not found", bindingID)
			}

			if err := store.WithTx(cmd.Context(), func(tx storage.Storage) error {
				if err := tx.DeleteActorRoleBinding(cmd.Context(), id); err != nil {
					if errors.Is(err, storage.ErrRoleBindingNotFound) {
						return fmt.Errorf("binding %s not found", bindingID)
					}
					return fmt.Errorf("delete binding: %w", err)
				}
				payload := map[string]any{
					"binding_id":    string(matched.ID),
					"actor_kind":    string(matched.Actor.Kind),
					"actor_subject": matched.Actor.Subject,
					"role":          string(matched.Role),
					"revoked_by":    string(callingActor.Kind) + ":" + callingActor.Subject,
				}
				if err := emitAuditEvent(cmd.Context(), tx, domain.EventRoleBindingRevoked, callingActor, "actor_role_binding", string(matched.ID), payload); err != nil {
					return err
				}
				return nil
			}); err != nil {
				return err
			}

			_, err = fmt.Fprintf(cmd.OutOrStdout(),
				"revoked binding %s (%s:%s -> %s)\n",
				shortID(matched.ID), matched.Actor.Kind, matched.Actor.Subject, matched.Role)
			return err
		},
	}
	cmd.Flags().StringVar(&bindingID, "binding", "", "id of the binding to revoke (required)")
	_ = cmd.MarkFlagRequired("binding")
	return cmd
}

// ----- shared helpers -----

// parseActorRef splits "kind:subject" into its components. It enforces
// the kind component is one of the known ActorKind constants so a
// typo doesn't silently land an unreachable binding.
func parseActorRef(s string) (kind, subject string, err error) {
	if s == "" {
		return "", "", fmt.Errorf("actor reference is empty")
	}
	idx := strings.IndexByte(s, ':')
	if idx <= 0 || idx == len(s)-1 {
		return "", "", fmt.Errorf("actor %q must be kind:subject (e.g. human:alice@example.com)", s)
	}
	kind = s[:idx]
	subject = s[idx+1:]
	switch domain.ActorKind(kind) {
	case domain.ActorHuman, domain.ActorServiceAccount, domain.ActorSystem:
	default:
		return "", "", fmt.Errorf("invalid actor kind %q (want human|service_account|system)", kind)
	}
	return kind, subject, nil
}

// allRoleNames renders the role enum for help text and error messages.
func allRoleNames() string {
	roles := domain.AllRoles()
	out := make([]string, len(roles))
	for i, r := range roles {
		out[i] = string(r)
	}
	return strings.Join(out, "|")
}
