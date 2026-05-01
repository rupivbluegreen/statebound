// Package cli — key subcommand. Phase 8 wave A surfaces the
// signing_keys table to operators so they can generate, list, and
// disable Ed25519 signing keys from the terminal. Plans are signed at
// generation time and verified at apply time using one of the keys
// listed here; see plan.go and apply.go for the integration.
//
// Key invariants:
//   - The private key bytes are NEVER stored in the database. They live
//     on disk (PEM file, mode 0600) or in an env var. The DB row holds
//     only the public key, fingerprint, and a private_key_ref string.
//   - `key generate` writes the private key to --output (default
//     ~/.statebound/signing-keys/<key-id>.pem) with O_EXCL + 0600. A
//     subsequent run with the same path refuses to overwrite.
//   - `key generate` and `key disable` require the calling actor to
//     hold rbac:manage (admin). `key list` is read-only and ungated.
//   - Operators set STATEBOUND_SIGNING_KEY_ID=<key-id> so the plan
//     subcommand picks up the right key. The CLI surfaces a clear hint
//     after generate.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/signing"
	"statebound.dev/statebound/internal/storage"
)

// EnvSigningKeyID is the operator-facing env var that names the active
// signing key. The plan subcommand reads it; key generate prints it as
// a hint.
const EnvSigningKeyID = "STATEBOUND_SIGNING_KEY_ID"

// EnvDevSkipPlanSignature toggles dev-mode skip for plan signing AND
// apply-time signature verification. Setting it to "true" lets a
// developer plan and apply without a signing key configured. It MUST
// remain unset in production.
const EnvDevSkipPlanSignature = "STATEBOUND_DEV_SKIP_PLAN_SIGNATURE"

// addKeyCmd registers `statebound key` and its subcommands on parent.
func addKeyCmd(parent *cobra.Command) {
	cmd := &cobra.Command{
		Use:   "key",
		Short: "Manage Ed25519 signing keys for plan bundles",
		Long: "Plans are signed at generation time and verified at apply " +
			"time. `key generate` mints a new keypair (DB row + on-disk " +
			"private key file). `key list` shows the registered keys. " +
			"`key disable` flips the disabled flag on a key, blocking it " +
			"from issuing new signatures and from validating at apply.",
	}
	cmd.AddCommand(newKeyGenerateCmd(), newKeyListCmd(), newKeyDisableCmd())
	parent.AddCommand(cmd)
}

// ----- generate -----

func newKeyGenerateCmd() *cobra.Command {
	var (
		keyID   string
		note    string
		expires string
		output  string
	)
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate a new Ed25519 signing keypair",
		Long: "Creates a fresh Ed25519 signing key. The public half is " +
			"persisted to signing_keys; the private half is written to " +
			"--output (PEM, mode 0600). Operators set " +
			EnvSigningKeyID + "=<key-id> so subsequent " +
			"`statebound plan` invocations sign with this key.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if keyID == "" {
				return fmt.Errorf("--key-id is required")
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
			if output == "" {
				home, err := os.UserHomeDir()
				if err != nil {
					return fmt.Errorf("resolve home directory for default --output: %w", err)
				}
				output = signing.DefaultPrivateKeyPath(filepath.Join(home, ".statebound"), keyID)
			}

			store, err := storeFromCmd(cmd)
			if err != nil {
				return err
			}
			defer func() { _ = store.Close(cmd.Context()) }()

			actor := actorFromCmd(cmd)
			if err := requireCapability(cmd.Context(), store, cmd.ErrOrStderr(), actor, domain.CapabilityRoleManage); err != nil {
				return err
			}

			return runKeyGenerate(cmd.Context(), store, cmd.OutOrStdout(), cmd.ErrOrStderr(), keyGenerateArgs{
				keyID:     keyID,
				note:      note,
				expiresAt: expiresAt,
				output:    output,
				actor:     actor,
			})
		},
	}
	cmd.Flags().StringVar(&keyID, "key-id", "", "logical key id (required, e.g. release-2026-q2)")
	cmd.Flags().StringVar(&note, "note", "", "optional free-form note recorded with the key")
	cmd.Flags().StringVar(&expires, "expires", "", "optional duration after which the key expires (e.g. 8760h)")
	cmd.Flags().StringVarP(&output, "output", "o", "", "private key file path; default ~/.statebound/signing-keys/<key-id>.pem")
	_ = cmd.MarkFlagRequired("key-id")
	return cmd
}

type keyGenerateArgs struct {
	keyID     string
	note      string
	expiresAt *time.Time
	output    string
	actor     domain.Actor
}

func runKeyGenerate(ctx context.Context, store storage.Storage, stdout, stderr io.Writer, args keyGenerateArgs) error {
	priv, pub, err := signing.Generate()
	if err != nil {
		return fmt.Errorf("generate ed25519 key: %w", err)
	}
	fingerprint := signing.Fingerprint(pub)
	privRef := "file:" + args.output

	key, err := domain.NewSigningKey(
		args.keyID,
		domain.AlgorithmEd25519,
		pub,
		priv,
		fingerprint,
		privRef,
		args.actor,
		args.expiresAt,
		args.note,
	)
	if err != nil {
		return fmt.Errorf("build signing key: %w", err)
	}

	// Write the private key to disk BEFORE the DB insert so a failure to
	// write the file does not leave a database row whose private_key_ref
	// points to a missing path. SaveKeyFile is O_EXCL: a pre-existing
	// file is an error.
	if err := signing.SaveKeyFile(args.output, priv); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}

	if err := store.WithTx(ctx, func(tx storage.Storage) error {
		if err := tx.AppendSigningKey(ctx, key); err != nil {
			if errors.Is(err, storage.ErrAlreadyExists) {
				return fmt.Errorf("key id %q already exists", args.keyID)
			}
			return fmt.Errorf("append signing key: %w", err)
		}
		payload := map[string]any{
			"key_id":          key.KeyID,
			"algorithm":       key.Algorithm,
			"fingerprint":     key.Fingerprint,
			"private_key_ref": key.PrivateKeyRef,
			"note":            key.Note,
		}
		if key.ExpiresAt != nil {
			payload["expires_at"] = key.ExpiresAt.UTC().Format(time.RFC3339)
		}
		return emitAuditEvent(ctx, tx, domain.EventSigningKeyGenerated, args.actor,
			"signing_key", key.KeyID, payload)
	}); err != nil {
		// Best-effort cleanup: the row failed to insert, so the on-disk
		// file is orphaned. We don't auto-delete (the operator may want
		// to inspect it); we surface a clear pointer instead.
		_, _ = fmt.Fprintf(stderr,
			"WARNING: signing key file written to %s but DB insert failed; remove the file and retry.\n",
			args.output)
		return err
	}

	_, _ = fmt.Fprintf(stdout,
		"signing key %s generated\n  fingerprint:     %s\n  private key:     %s\n  private_key_ref: %s\n",
		key.KeyID, key.Fingerprint, args.output, key.PrivateKeyRef)
	_, _ = fmt.Fprintf(stderr,
		"hint: export %s=%s before `statebound plan` to sign plans with this key\n",
		EnvSigningKeyID, key.KeyID)
	return nil
}

// ----- list -----

func newKeyListCmd() *cobra.Command {
	var (
		includeDisabled bool
		format          string
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List registered signing keys",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, err := storeFromCmd(cmd)
			if err != nil {
				return err
			}
			defer func() { _ = store.Close(cmd.Context()) }()

			keys, err := store.ListSigningKeys(cmd.Context(), !includeDisabled)
			if err != nil {
				return fmt.Errorf("list signing keys: %w", err)
			}
			return renderSigningKeys(cmd.OutOrStdout(), keys, format)
		},
	}
	cmd.Flags().BoolVar(&includeDisabled, "include-disabled", false, "include disabled and expired keys in the output")
	cmd.Flags().StringVar(&format, "format", "table", "output format: table or json")
	return cmd
}

type signingKeyView struct {
	KeyID         string     `json:"key_id"`
	Algorithm     string     `json:"algorithm"`
	Fingerprint   string     `json:"fingerprint"`
	PrivateKeyRef string     `json:"private_key_ref"`
	CreatedBy     string     `json:"created_by"`
	CreatedAt     time.Time  `json:"created_at"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	Disabled      bool       `json:"disabled"`
	Note          string     `json:"note,omitempty"`
	LastUsedAt    *time.Time `json:"last_used_at,omitempty"`
}

func toSigningKeyView(k *domain.SigningKey) signingKeyView {
	return signingKeyView{
		KeyID:         k.KeyID,
		Algorithm:     k.Algorithm,
		Fingerprint:   k.Fingerprint,
		PrivateKeyRef: k.PrivateKeyRef,
		CreatedBy:     string(k.CreatedBy.Kind) + ":" + k.CreatedBy.Subject,
		CreatedAt:     k.CreatedAt.UTC(),
		ExpiresAt:     k.ExpiresAt,
		Disabled:      k.Disabled,
		Note:          k.Note,
		LastUsedAt:    k.LastUsedAt,
	}
}

func renderSigningKeys(w io.Writer, keys []*domain.SigningKey, format string) error {
	switch strings.ToLower(format) {
	case "json":
		out := make([]signingKeyView, 0, len(keys))
		for _, k := range keys {
			out = append(out, toSigningKeyView(k))
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	case "", "table":
		return renderSigningKeysTable(w, keys)
	default:
		return fmt.Errorf("unknown --format %q (want table or json)", format)
	}
}

func renderSigningKeysTable(w io.Writer, keys []*domain.SigningKey) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "KEY_ID\tFINGERPRINT\tDISABLED\tEXPIRES\tCREATED_BY\tNOTE"); err != nil {
		return err
	}
	for _, k := range keys {
		expires := "never"
		if k.ExpiresAt != nil {
			expires = k.ExpiresAt.UTC().Format(time.RFC3339)
		}
		fp := shortFingerprint(k.Fingerprint)
		disabled := "no"
		if k.Disabled {
			disabled = "yes"
		}
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			k.KeyID, fp, disabled, expires,
			string(k.CreatedBy.Kind)+":"+k.CreatedBy.Subject, k.Note); err != nil {
			return err
		}
	}
	return tw.Flush()
}

// shortFingerprint trims a "sha256:<64hex>" fingerprint to "sha256:<8hex>…"
// so the table column stays narrow. The full fingerprint stays in JSON
// output and audit events.
func shortFingerprint(fp string) string {
	if fp == "" {
		return ""
	}
	prefix, hex, ok := strings.Cut(fp, ":")
	if !ok {
		return fp
	}
	if len(hex) <= 12 {
		return fp
	}
	return prefix + ":" + hex[:12] + ".."
}

// ----- disable -----

func newKeyDisableCmd() *cobra.Command {
	var (
		keyID  string
		enable bool
	)
	cmd := &cobra.Command{
		Use:   "disable",
		Short: "Disable (or re-enable) a signing key by id",
		Long: "Sets disabled = TRUE on the named key, blocking it from " +
			"issuing new signatures and from validating at apply time. " +
			"Pass --enable to flip the flag back. The row is never " +
			"deleted: the audit history must outlive the key itself.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if keyID == "" {
				return fmt.Errorf("--key-id is required")
			}
			store, err := storeFromCmd(cmd)
			if err != nil {
				return err
			}
			defer func() { _ = store.Close(cmd.Context()) }()

			actor := actorFromCmd(cmd)
			if err := requireCapability(cmd.Context(), store, cmd.ErrOrStderr(), actor, domain.CapabilityRoleManage); err != nil {
				return err
			}

			disable := !enable
			return store.WithTx(cmd.Context(), func(tx storage.Storage) error {
				if err := tx.DisableSigningKey(cmd.Context(), keyID, disable); err != nil {
					if errors.Is(err, storage.ErrSigningKeyNotFound) {
						return fmt.Errorf("signing key %q not found", keyID)
					}
					return fmt.Errorf("toggle signing key disabled: %w", err)
				}
				payload := map[string]any{
					"key_id":   keyID,
					"disabled": disable,
				}
				kind := domain.EventSigningKeyDisabled
				if !disable {
					// Re-enable still records under the same kind so an
					// auditor sees the toggle history; the payload
					// "disabled":false makes the direction unambiguous.
					kind = domain.EventSigningKeyDisabled
				}
				if err := emitAuditEvent(cmd.Context(), tx, kind, actor, "signing_key", keyID, payload); err != nil {
					return err
				}
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "signing key %s disabled=%t\n", keyID, disable)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&keyID, "key-id", "", "key id to disable (required)")
	cmd.Flags().BoolVar(&enable, "enable", false, "re-enable a previously disabled key")
	_ = cmd.MarkFlagRequired("key-id")
	return cmd
}
