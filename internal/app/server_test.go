package app

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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
