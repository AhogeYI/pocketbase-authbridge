// Package authbridge turns PocketBase into the identity issuer for your
// standalone services, Supabase-style: every successful
// authentication of an application user additionally mints a short-lived
// HS256 "service token" — a JWT carrying just the user id — that resource
// servers verify offline with the shared secret (pbext/authtoken).
//
// Two surfaces, one token:
//
//	POST /api/authbridge/v1/token   (PocketBase auth required) → explicit mint
//	auth responses                  meta.serviceToken on every login/refresh
//	                                (OnRecordAuthRequest hook — the client's
//	                                existing 401→refresh loop keeps working
//	                                with zero extra calls)
//
// Superusers never receive service tokens: the bridge speaks for application
// users, not for the admin plane. Like authsms, the extension is
// fail-closed: without a usable AUTHBRIDGE_SHARED_SECRET it stays dark — no
// route, no hook, no tokens.
//
// Environment:
//
//	AUTHBRIDGE_SHARED_SECRET  required to activate (>= 32 chars; the same
//	                          value every verifying service holds)
//	AUTHBRIDGE_TOKEN_TTL      token lifetime (Go duration, default 1h —
//	                          offline verification has no revocation, so the
//	                          window stays short; refresh is free via the hook)
//	AUTHBRIDGE_ISSUER         issuer claim (default "authbridge")
package authbridge

import (
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/Ahogeyi/pocketbase-authbridge/authtoken"

	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
)

const (
	envSecret = "AUTHBRIDGE_SHARED_SECRET"
	envTTL    = "AUTHBRIDGE_TOKEN_TTL"
	envIssuer = "AUTHBRIDGE_ISSUER"

	defaultTTL    = time.Hour
	defaultIssuer = "authbridge"

	metaToken     = "serviceToken"
	metaTokenType = "serviceTokenType"
	metaExpiresAt = "serviceTokenExpiresAt"
)

type config struct {
	secret []byte
	ttl    time.Duration
	issuer string
}

// loadConfig returns ok=false when the extension must stay dark.
func loadConfig() (config, bool) {
	secret := os.Getenv(envSecret)
	if len(secret) < authtoken.MinSecretLen {
		return config{}, false
	}
	ttl := defaultTTL
	if raw := os.Getenv(envTTL); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil && parsed > 0 {
			ttl = parsed
		}
	}
	issuer := os.Getenv(envIssuer)
	if issuer == "" {
		issuer = defaultIssuer
	}
	return config{secret: []byte(secret), ttl: ttl, issuer: issuer}, true
}

// Register mounts the explicit mint route and the auth-response hook. Call
// from the binary's setup, before serve.
func Register(app core.App) {
	app.OnServe().BindFunc(func(e *core.ServeEvent) error {
		cfg, ok := loadConfig()
		if !ok {
			app.Logger().Warn("[authbridge] " + envSecret +
				" missing or shorter than 32 chars — service tokens disabled")
			return e.Next()
		}

		e.Router.POST("/api/authbridge/v1/token", handleToken(cfg)).
			Bind(apis.RequireAuth())

		app.OnRecordAuthRequest().BindFunc(func(e *core.RecordAuthRequestEvent) error {
			if !e.Record.IsSuperuser() {
				mergeServiceToken(e, cfg)
			}
			return e.Next()
		})

		app.Logger().Info("[authbridge] service tokens enabled",
			slog.String("issuer", cfg.issuer), slog.Duration("ttl", cfg.ttl))
		return e.Next()
	})
}

func handleToken(cfg config) func(*core.RequestEvent) error {
	return func(e *core.RequestEvent) error {
		if e.Auth == nil || e.Auth.IsSuperuser() {
			return e.ForbiddenError("Service tokens are for application users.", nil)
		}
		token, expiresAt, err := mint(cfg, e.Auth.Id)
		if err != nil {
			return e.InternalServerError("Failed to issue the service token.", err)
		}
		return e.JSON(http.StatusOK, map[string]any{
			"token":     token,
			"tokenType": "Bearer",
			"expiresAt": expiresAt.UTC().Format(time.RFC3339),
		})
	}
}

// mergeServiceToken adds the freshly minted token to the auth response meta.
// The authentication itself must never fail because of the bridge: on a mint
// error the response simply ships without the service token.
func mergeServiceToken(e *core.RecordAuthRequestEvent, cfg config) {
	token, expiresAt, err := mint(cfg, e.Record.Id)
	if err != nil {
		e.App.Logger().Error("[authbridge] service token mint failed",
			slog.String("error", err.Error()))
		return
	}
	meta := map[string]any{}
	if existing, ok := e.Meta.(map[string]any); ok {
		for k, v := range existing {
			meta[k] = v
		}
	} else if e.Meta != nil {
		// A non-map meta we do not understand: never clobber it.
		return
	}
	meta[metaToken] = token
	meta[metaTokenType] = "Bearer"
	meta[metaExpiresAt] = expiresAt.UTC().Format(time.RFC3339)
	e.Meta = meta
}

func mint(cfg config, userID string) (string, time.Time, error) {
	claims := authtoken.NewClaims(cfg.issuer, userID, cfg.ttl)
	token, err := authtoken.Sign(claims, cfg.secret)
	return token, claims.ExpiresAt, err
}
