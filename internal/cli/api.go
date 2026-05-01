// Package cli — `statebound api serve`. Phase 8 wave B.
//
// The api subcommand boots the HTTP API server from internal/api against
// the configured Postgres DSN. The reasoning add-on (and any other
// authenticated client) consumes this surface; humans normally use the
// CLI directly.
//
// Auth modes:
//   - OIDC: pass --oidc-issuer <url> --oidc-audience <client-id>. The
//     server fetches JWKS at boot and validates RS256/ES256 JWTs on
//     every request.
//   - Dev: pass --dev-token <token> [--dev-actor kind:subject]. Every
//     request whose Authorization: Bearer matches the configured token
//     runs as the configured actor with the actor's currently active
//     roles.
//
// Refusal: starting the server with neither --oidc-issuer nor --dev-token
// is an error. Unauthenticated APIs in regulated environments are not a
// thing we ship.
package cli

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"statebound.dev/statebound/internal/api"
)

// API server env-var names. The CLI reads these as fallbacks for
// --listen, --oidc-issuer, --oidc-audience, --dev-token, --dev-actor
// so an operator can drop the flags from their wrapper script.
const (
	envAPIListen       = "STATEBOUND_API_LISTEN"
	envAPIOIDCIssuer   = "STATEBOUND_API_OIDC_ISSUER"
	envAPIOIDCAudience = "STATEBOUND_API_OIDC_AUDIENCE"
	envAPIDevToken     = "STATEBOUND_DEV_TOKEN"
	envAPIDevActor     = "STATEBOUND_DEV_ACTOR"
)

// addAPICmd registers `statebound api` and its subcommands on parent.
func addAPICmd(parent *cobra.Command) {
	cmd := &cobra.Command{
		Use:   "api",
		Short: "HTTP API server (read-only) for the reasoning add-on and other clients",
		Long: "The api subcommand exposes the core's read surface over " +
			"HTTP. Write operations remain CLI-only in v0.8 — agents " +
			"never mutate approved state through this server.",
	}
	cmd.AddCommand(newAPIServeCmd())
	parent.AddCommand(cmd)
}

func newAPIServeCmd() *cobra.Command {
	var (
		listen        string
		oidcIssuer    string
		oidcAudience  string
		devToken      string
		devActor      string
		readTimeout   time.Duration
		writeTimeout  time.Duration
	)
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the HTTP API server",
		Long: "Boots the HTTP API server. At least one of --oidc-issuer " +
			"or --dev-token MUST be set; an unauthenticated server is " +
			"refused. The server binds --listen and runs until SIGINT " +
			"or SIGTERM, then drains in-flight requests gracefully.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := api.Config{
				Listen:       firstNonEmpty(listen, os.Getenv(envAPIListen), ":8080"),
				OIDCIssuer:   firstNonEmpty(oidcIssuer, os.Getenv(envAPIOIDCIssuer)),
				OIDCAudience: firstNonEmpty(oidcAudience, os.Getenv(envAPIOIDCAudience)),
				DevToken:     firstNonEmpty(devToken, os.Getenv(envAPIDevToken)),
				StaticActor:  firstNonEmpty(devActor, os.Getenv(envAPIDevActor)),
				ReadTimeout:  readTimeout,
				WriteTimeout: writeTimeout,
			}

			if cfg.OIDCIssuer == "" && cfg.DevToken == "" {
				return fmt.Errorf("api serve: pass --oidc-issuer / --oidc-audience for production or --dev-token for local development; refusing to start unauthenticated")
			}

			store, err := storeFromCmd(cmd)
			if err != nil {
				return err
			}
			defer func() { _ = store.Close(cmd.Context()) }()

			srv, err := api.New(cmd.Context(), cfg, store)
			if err != nil {
				return fmt.Errorf("build api server: %w", err)
			}

			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			_, _ = fmt.Fprintf(cmd.ErrOrStderr(),
				"statebound api serving on %s\n", cfg.Listen)
			if err := srv.Start(ctx); err != nil {
				return fmt.Errorf("api serve: %w", err)
			}
			_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "statebound api stopped")
			return nil
		},
	}
	cmd.Flags().StringVar(&listen, "listen", "", "address to bind, e.g. :8080 (env "+envAPIListen+", default :8080)")
	cmd.Flags().StringVar(&oidcIssuer, "oidc-issuer", "", "OIDC issuer URL (env "+envAPIOIDCIssuer+")")
	cmd.Flags().StringVar(&oidcAudience, "oidc-audience", "", "OIDC client/audience id (env "+envAPIOIDCAudience+")")
	cmd.Flags().StringVar(&devToken, "dev-token", "", "static dev bearer token; mutually exclusive with --oidc-issuer in practice (env "+envAPIDevToken+")")
	cmd.Flags().StringVar(&devActor, "dev-actor", "", "dev-mode actor as kind:subject; default human:dev (env "+envAPIDevActor+")")
	cmd.Flags().DurationVar(&readTimeout, "read-timeout", 0, "HTTP read timeout (default 15s)")
	cmd.Flags().DurationVar(&writeTimeout, "write-timeout", 0, "HTTP write timeout (default 30s)")
	return cmd
}

// firstNonEmpty returns the first non-empty value from xs. Used for
// flag/env/default fallback chains.
func firstNonEmpty(xs ...string) string {
	for _, s := range xs {
		if s != "" {
			return s
		}
	}
	return ""
}
