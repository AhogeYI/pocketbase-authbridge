// authbridge tests: the real PocketBase router + hook chain, same harness
// pattern as the gateway tests (apis.NewRouter → OnServe trigger → mux).
package authbridge

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/Ahogeyi/pocketbase-authbridge/authtoken"

	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"

	// system-table migrations (_collections & friends): PocketBase framework
	// mode requires the app to register them before bootstrap creates a fresh
	// database (the root module does it via internal/schema).
	_ "github.com/pocketbase/pocketbase/migrations"
)

const testSecret = "authbridge-test-secret-0123456789abcdef"

// newApp boots a PB app with the extension registered and the serve hooks
// fired, returning the ready mux. PB seeds a default users auth collection
// on a fresh database, which is all the bridge needs.
func newApp(t *testing.T, withSecret bool) (http.Handler, *core.BaseApp) {
	t.Helper()
	if withSecret {
		t.Setenv("AUTHBRIDGE_SHARED_SECRET", testSecret)
		t.Setenv("AUTHBRIDGE_ISSUER", "test-bridge")
	}
	app := core.NewBaseApp(core.BaseAppConfig{
		DataDir:       t.TempDir(),
		EncryptionEnv: "pb_authbridge_test_env",
	})
	if err := app.Bootstrap(); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	app.Settings().Logs.MinLevel = 100 // keep test output quiet
	t.Cleanup(func() {
		_ = app.ResetBootstrapState()
		_ = os.RemoveAll(app.DataDir())
	})

	Register(app)

	router, err := apis.NewRouter(app)
	if err != nil {
		t.Fatalf("init router: %v", err)
	}
	serveEvent := &core.ServeEvent{App: app, Router: router, Server: &http.Server{}}
	var mux http.Handler
	if err := app.OnServe().Trigger(serveEvent, func(e *core.ServeEvent) error {
		mux, err = e.Router.BuildMux()
		return err
	}); err != nil {
		t.Fatalf("serve trigger: %v", err)
	}
	return mux, app
}

func newUser(t *testing.T, app *core.BaseApp) *core.Record {
	t.Helper()
	users, err := app.FindCollectionByNameOrId("users")
	if err != nil {
		t.Fatalf("users collection: %v", err)
	}
	user := core.NewRecord(users)
	user.Set("email", "bridge-test@example.com")
	user.Set("name", "Bridge Test")
	user.SetVerified(true)
	user.SetPassword("password123")
	if err := app.Save(user); err != nil {
		t.Fatalf("save user: %v", err)
	}
	return user
}

func newSuperuser(t *testing.T, app *core.BaseApp) *core.Record {
	t.Helper()
	superusers, err := app.FindCollectionByNameOrId(core.CollectionNameSuperusers)
	if err != nil {
		t.Fatalf("superusers collection: %v", err)
	}
	su := core.NewRecord(superusers)
	su.Set("email", "bridge-admin@example.com")
	su.SetPassword("password123")
	if err := app.Save(su); err != nil {
		t.Fatalf("save superuser: %v", err)
	}
	return su
}

// triggerAuth fires the OnRecordAuthRequest chain for record the way
// apis.RecordAuthResponse does, with the given starting meta.
func triggerAuth(t *testing.T, app *core.BaseApp, record *core.Record, meta any) *core.RecordAuthRequestEvent {
	t.Helper()
	event := &core.RecordAuthRequestEvent{
		RequestEvent: &core.RequestEvent{App: app},
		Record:       record,
		Token:        "pb-token",
		Meta:         meta,
		AuthMethod:   "password",
	}
	if err := app.OnRecordAuthRequest().Trigger(event, func(*core.RecordAuthRequestEvent) error {
		return nil
	}); err != nil {
		t.Fatalf("auth trigger: %v", err)
	}
	return event
}

func TestAuthResponseCarriesServiceToken(t *testing.T) {
	_, app := newApp(t, true)
	user := newUser(t, app)

	event := triggerAuth(t, app, user, map[string]any{"existing": "kept"})

	meta, ok := event.Meta.(map[string]any)
	if !ok {
		t.Fatalf("meta = %#v, want a map", event.Meta)
	}
	if meta["existing"] != "kept" {
		t.Error("existing meta keys were clobbered")
	}
	token, _ := meta[metaToken].(string)
	if token == "" {
		t.Fatal("auth response meta carries no serviceToken")
	}
	claims, err := authtoken.Parse(token, []byte(testSecret), "test-bridge")
	if err != nil {
		t.Fatalf("service token does not verify: %v", err)
	}
	if claims.Subject != user.Id {
		t.Errorf("subject = %q, want the user id %q", claims.Subject, user.Id)
	}
}

func TestSuperuserGetsNoServiceToken(t *testing.T) {
	_, app := newApp(t, true)
	su := newSuperuser(t, app)

	event := triggerAuth(t, app, su, nil)
	if event.Meta != nil {
		t.Fatalf("superuser auth meta = %#v, want nil", event.Meta)
	}
}

func TestTokenEndpointIssuesForUser(t *testing.T) {
	mux, app := newApp(t, true)
	user := newUser(t, app)
	token, err := user.NewAuthToken()
	if err != nil {
		t.Fatalf("auth token: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/authbridge/v1/token", nil)
	req.Header.Set("Authorization", token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	// The token body is verified by TestAuthResponseCarriesServiceToken's
	// claims checks; here the shape matters.
	body := rec.Body.String()
	for _, want := range []string{`"token"`, `"tokenType":"Bearer"`, `"expiresAt"`} {
		if !strings.Contains(body, want) {
			t.Errorf("response body missing %s: %s", want, body)
		}
	}
}

func TestTokenEndpointRejectsSuperuserAndAnonymous(t *testing.T) {
	mux, app := newApp(t, true)
	su := newSuperuser(t, app)
	suToken, _ := su.NewAuthToken()

	// Anonymous: RequireAuth answers 401 before the handler runs.
	req := httptest.NewRequest(http.MethodPost, "/api/authbridge/v1/token", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous status = %d, want 401", rec.Code)
	}

	// Superuser: authenticated, but the bridge speaks for app users only.
	req = httptest.NewRequest(http.MethodPost, "/api/authbridge/v1/token", nil)
	req.Header.Set("Authorization", suToken)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("superuser status = %d, want 403", rec.Code)
	}
}

func TestDarkWithoutSecret(t *testing.T) {
	mux, app := newApp(t, false) // no AUTHBRIDGE_SHARED_SECRET
	user := newUser(t, app)

	req := httptest.NewRequest(http.MethodPost, "/api/authbridge/v1/token", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("route status without secret = %d, want 404 (dark)", rec.Code)
	}

	event := triggerAuth(t, app, user, nil)
	if event.Meta != nil {
		t.Errorf("meta without secret = %#v, want nil (dark)", event.Meta)
	}
}
