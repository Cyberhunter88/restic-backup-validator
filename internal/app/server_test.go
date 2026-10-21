package app

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewServerRejectsDiscoveryURLAsIssuer(t *testing.T) {
	_, err := NewServer(context.Background(), ServerConfig{
		PublicURL: "https://validator.example.invalid",
		Issuer: "https://sso.example.invalid/oidc/.well-known/openid-configuration/",
		ClientID: "example-client", ClientSecret: "example-secret",
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "OIDC_ISSUER muss die Issuer-URL sein") {
		t.Fatalf("unexpected issuer validation error: %v", err)
	}
}

func TestLoginRequestsGroupsScope(t *testing.T) {
	var issuer string
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"jwks_uri":%q}`,
			issuer, issuer+"/authorize", issuer+"/token", issuer+"/keys")
	}))
	defer provider.Close()
	issuer = provider.URL

	store, err := OpenStore(filepath.Join(t.TempDir(), "state.db"), testKey())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	s, err := NewServer(context.Background(), ServerConfig{
		PublicURL: "https://validator.example.invalid", Issuer: issuer,
		ClientID: "client", ClientSecret: "secret",
	}, store)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	response := httptest.NewRecorder()
	s.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/login", nil))
	if response.Code != http.StatusSeeOther {
		t.Fatalf("login response: %d", response.Code)
	}
	redirect, err := url.Parse(response.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(" "+redirect.Query().Get("scope")+" ", " groups ") {
		t.Fatalf("login does not request groups scope: %q", redirect.Query().Get("scope"))
	}
}

func TestPublicHTTPRequiresSessionAndAdmin(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "state.db"), testKey())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	s := &Server{store: store, runner: NewRunner(store), sessions: map[string]session{
		"reader": {Subject: "reader", CSRF: "reader-csrf", Expires: time.Now().Add(time.Hour)},
		"admin":  {Subject: "admin", Admin: true, CSRF: "admin-csrf", Expires: time.Now().Add(time.Hour)},
	}}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()
	s.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/login" {
		t.Fatalf("unauthenticated response: %d", response.Code)
	}
	if response.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("CSP missing")
	}
	request = httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(&http.Cookie{Name: "validator_session", Value: "reader"})
	response = httptest.NewRecorder()
	s.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Backup-Prüfungen") {
		t.Fatalf("reader overview failed: %d", response.Code)
	}
	if strings.Contains(response.Body.String(), "Repository hinzufügen") {
		t.Fatal("reader saw admin controls")
	}

	form := url.Values{"csrf": {"reader-csrf"}, "id": {"any"}}
	request = httptest.NewRequest(http.MethodPost, "/repository/delete", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: "validator_session", Value: "reader"})
	response = httptest.NewRecorder()
	s.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("reader could delete: %d", response.Code)
	}

	form.Set("csrf", "wrong")
	request = httptest.NewRequest(http.MethodPost, "/repository/delete", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: "validator_session", Value: "admin"})
	response = httptest.NewRecorder()
	s.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("invalid CSRF accepted: %d", response.Code)
	}
}
