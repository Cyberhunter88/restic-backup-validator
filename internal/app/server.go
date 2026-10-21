package app

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/robfig/cron/v3"
	"golang.org/x/oauth2"
)

type ServerConfig struct {
	Listen       string
	PublicURL    string
	Issuer       string
	ClientID     string
	ClientSecret string
	GroupClaim   string
}

type session struct {
	Subject string
	Admin   bool
	CSRF    string
	Expires time.Time
}

type pendingLogin struct {
	Nonce    string
	Verifier string
	Expires  time.Time
}

type Server struct {
	config     ServerConfig
	store      *Store
	runner     *Runner
	oauth      oauth2.Config
	verifier   *oidc.IDTokenVerifier
	mu         sync.Mutex
	sessions   map[string]session
	pending    map[string]pendingLogin
	scheduleMu sync.Mutex
	scheduler  *cron.Cron
}

//go:embed style.css
var styleCSS string

func NewServer(ctx context.Context, config ServerConfig, store *Store) (*Server, error) {
	if config.Listen == "" {
		config.Listen = ":8080"
	}
	if config.GroupClaim == "" {
		config.GroupClaim = "groups"
	}
	public, err := url.Parse(config.PublicURL)
	if err != nil || public.Scheme != "https" || public.Host == "" || public.User != nil ||
		(public.Path != "" && public.Path != "/") || public.RawQuery != "" || public.Fragment != "" {
		return nil, errors.New("APP_URL muss eine öffentliche HTTPS-Adresse sein")
	}
	if config.Issuer == "" || config.ClientID == "" || config.ClientSecret == "" {
		return nil, errors.New("OIDC-Konfiguration ist unvollständig")
	}
	if strings.HasSuffix(strings.TrimRight(config.Issuer, "/"), "/.well-known/openid-configuration") {
		return nil, errors.New("OIDC_ISSUER muss die Issuer-URL sein, nicht die Discovery-URL mit /.well-known/openid-configuration")
	}
	provider, err := oidc.NewProvider(ctx, config.Issuer)
	if err != nil {
		return nil, fmt.Errorf("OIDC Discovery fehlgeschlagen: %w", err)
	}
	s := &Server{config: config, store: store, runner: NewRunner(store), verifier: provider.Verifier(&oidc.Config{ClientID: config.ClientID}),
		sessions: make(map[string]session), pending: make(map[string]pendingLogin)}
	s.oauth = oauth2.Config{ClientID: config.ClientID, ClientSecret: config.ClientSecret, Endpoint: provider.Endpoint(),
		RedirectURL: strings.TrimRight(config.PublicURL, "/") + "/callback", Scopes: []string{oidc.ScopeOpenID, "profile", "email", "groups"}}
	if err := s.reloadSchedule(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Server) Close() {
	s.scheduleMu.Lock()
	if s.scheduler != nil {
		s.scheduler.Stop()
	}
	s.scheduleMu.Unlock()
}

func (s *Server) reloadSchedule() error {
	repos, err := s.store.ListRepositories()
	if err != nil {
		return err
	}
	c := cron.New(cron.WithParser(cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)))
	for _, r := range repos {
		if !r.Enabled {
			continue
		}
		id := r.ID
		if _, err := c.AddFunc("CRON_TZ="+r.Timezone+" "+r.Schedule, func() {
			if _, err := s.runner.Run(context.Background(), id, "schedule"); err != nil {
				slog.Error("scheduled run failed", "repository_id", id, "error", err)
			}
		}); err != nil {
			return err
		}
	}
	c.Start()
	s.scheduleMu.Lock()
	old := s.scheduler
	s.scheduler = c
	s.scheduleMu.Unlock()
	if old != nil {
		old.Stop()
	}
	return nil
}

func randomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func secureCookie(name, value string, maxAge int) *http.Cookie {
	return &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: maxAge}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	w.Header().Set("Cache-Control", "no-store")
	switch {
	case r.URL.Path == "/style.css" && r.Method == http.MethodGet:
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		_, _ = w.Write([]byte(styleCSS))
		return
	case r.URL.Path == "/healthz" && r.Method == http.MethodGet:
		w.WriteHeader(http.StatusNoContent)
		return
	case r.URL.Path == "/login" && r.Method == http.MethodGet:
		s.login(w, r)
		return
	case r.URL.Path == "/callback" && r.Method == http.MethodGet:
		s.callback(w, r)
		return
	}
	sess, ok := s.sessionFor(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodPost {
		if r.ContentLength > 65536 {
			http.Error(w, "Eingabe zu groß", http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 65536)
		if err := r.ParseForm(); err != nil || r.PostForm.Get("csrf") != sess.CSRF {
			http.Error(w, "Ungültige Anfrage", http.StatusForbidden)
			return
		}
	}
	switch {
	case r.URL.Path == "/" && r.Method == http.MethodGet:
		s.index(w, r, sess)
	case r.URL.Path == "/repository" && r.Method == http.MethodGet:
		s.edit(w, r, sess, "")
	case r.URL.Path == "/repository/save" && r.Method == http.MethodPost:
		s.save(w, r, sess)
	case r.URL.Path == "/repository/delete" && r.Method == http.MethodPost:
		s.delete(w, r, sess)
	case r.URL.Path == "/run" && r.Method == http.MethodPost:
		s.run(w, r)
	case r.URL.Path == "/webhook" && r.Method == http.MethodPost:
		s.webhook(w, r, sess)
	case r.URL.Path == "/logout" && r.Method == http.MethodPost:
		s.logout(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) sessionFor(r *http.Request) (session, bool) {
	c, err := r.Cookie("validator_session")
	if err != nil {
		return session{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[c.Value]
	if !ok || time.Now().After(sess.Expires) {
		delete(s.sessions, c.Value)
		return session{}, false
	}
	return sess, true
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	state, err := randomToken()
	if err != nil {
		http.Error(w, "Anmeldung nicht möglich", 500)
		return
	}
	nonce, err := randomToken()
	if err != nil {
		http.Error(w, "Anmeldung nicht möglich", 500)
		return
	}
	pkce := oauth2.GenerateVerifier()
	s.mu.Lock()
	for key, item := range s.pending {
		if time.Now().After(item.Expires) {
			delete(s.pending, key)
		}
	}
	if len(s.pending) >= 1024 {
		s.mu.Unlock()
		http.Error(w, "Zu viele Anmeldungen, bitte später erneut versuchen", http.StatusTooManyRequests)
		return
	}
	s.pending[state] = pendingLogin{Nonce: nonce, Verifier: pkce, Expires: time.Now().Add(5 * time.Minute)}
	s.mu.Unlock()
	http.SetCookie(w, secureCookie("validator_oidc_state", state, 300))
	redirect := s.oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(pkce))
	http.Redirect(w, r, redirect, http.StatusSeeOther)
}

func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("validator_oidc_state")
	state := r.URL.Query().Get("state")
	if err != nil || state == "" || cookie.Value != state {
		http.Error(w, "OIDC state ungültig", http.StatusForbidden)
		return
	}
	http.SetCookie(w, secureCookie("validator_oidc_state", "", -1))
	s.mu.Lock()
	pending, ok := s.pending[state]
	delete(s.pending, state)
	s.mu.Unlock()
	if !ok || time.Now().After(pending.Expires) {
		http.Error(w, "OIDC-Anmeldung abgelaufen", http.StatusForbidden)
		return
	}
	token, err := s.oauth.Exchange(r.Context(), r.URL.Query().Get("code"), oauth2.VerifierOption(pending.Verifier))
	if err != nil {
		http.Error(w, "OIDC Code-Austausch fehlgeschlagen", http.StatusForbidden)
		return
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "OIDC ID-Token fehlt", http.StatusForbidden)
		return
	}
	idToken, err := s.verifier.Verify(r.Context(), raw)
	if err != nil || idToken.Nonce != pending.Nonce {
		http.Error(w, "OIDC ID-Token ungültig", http.StatusForbidden)
		return
	}
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "OIDC Claims ungültig", http.StatusForbidden)
		return
	}
	admin := false
	switch groups := claims[s.config.GroupClaim].(type) {
	case []any:
		for _, v := range groups {
			if v == "backup_admin" {
				admin = true
			}
		}
	case []string:
		for _, v := range groups {
			if v == "backup_admin" {
				admin = true
			}
		}
	case string:
		admin = groups == "backup_admin"
	}
	sessionID, err := randomToken()
	if err != nil {
		http.Error(w, "Sitzung nicht möglich", 500)
		return
	}
	csrf, err := randomToken()
	if err != nil {
		http.Error(w, "Sitzung nicht möglich", 500)
		return
	}
	s.mu.Lock()
	for key, item := range s.sessions {
		if time.Now().After(item.Expires) {
			delete(s.sessions, key)
		}
	}
	if len(s.sessions) >= 10000 {
		s.mu.Unlock()
		http.Error(w, "Zu viele Sitzungen, bitte später erneut versuchen", http.StatusTooManyRequests)
		return
	}
	s.sessions[sessionID] = session{Subject: idToken.Subject, Admin: admin, CSRF: csrf, Expires: time.Now().Add(30 * time.Minute)}
	s.mu.Unlock()
	http.SetCookie(w, secureCookie("validator_session", sessionID, 1800))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("validator_session"); err == nil {
		s.mu.Lock()
		delete(s.sessions, c.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, secureCookie("validator_session", "", -1))
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func requireAdmin(w http.ResponseWriter, sess session) bool {
	if !sess.Admin {
		http.Error(w, "Nur backup_admin darf Einstellungen ändern", http.StatusForbidden)
		return false
	}
	return true
}

type page struct {
	Version    string
	Admin      bool
	CSRF       string
	Error      string
	Repo       Repository
	Repos      []Repository
	Runs       []Run
	WebhookSet bool
	Active     map[string]bool
}

var views = template.Must(template.New("pages").Parse(pageHTML))

func (s *Server) render(w http.ResponseWriter, name string, p page) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := views.ExecuteTemplate(w, name, p); err != nil {
		slog.Error("template failed", "error", err)
	}
}

func (s *Server) index(w http.ResponseWriter, r *http.Request, sess session) {
	repos, err := s.store.ListRepositories()
	if err != nil {
		http.Error(w, "Datenbankfehler", 500)
		return
	}
	runs, err := s.store.ListRuns("", 100)
	if err != nil {
		http.Error(w, "Datenbankfehler", 500)
		return
	}
	webhook, _ := s.store.Webhook()
	active := make(map[string]bool)
	for _, repo := range repos {
		active[repo.ID] = s.runner.IsActive(repo.ID)
	}
	s.render(w, "index", page{Version: Version, Admin: sess.Admin, CSRF: sess.CSRF, Repos: repos, Runs: runs, WebhookSet: webhook != "", Active: active})
}

func (s *Server) edit(w http.ResponseWriter, r *http.Request, sess session, message string) {
	if !requireAdmin(w, sess) {
		return
	}
	repo := Repository{Schedule: "0 3 * * *", Timezone: "Europe/Berlin", MaxAgeHours: 36, SubsetTotal: 7, NextSubset: 1, Enabled: true}
	if id := r.URL.Query().Get("id"); id != "" {
		var err error
		repo, err = s.store.GetRepository(id)
		if err != nil {
			http.NotFound(w, r)
			return
		}
	}
	s.render(w, "edit", page{Version: Version, Admin: true, CSRF: sess.CSRF, Repo: repo, Error: message})
}

func (s *Server) save(w http.ResponseWriter, r *http.Request, sess session) {
	if !requireAdmin(w, sess) {
		return
	}
	repo := Repository{ID: r.PostForm.Get("id"), Name: r.PostForm.Get("name"), Location: r.PostForm.Get("location"),
		Schedule: r.PostForm.Get("schedule"), Timezone: r.PostForm.Get("timezone"), MaxAgeHours: parsePositive(r.PostForm.Get("max_age_hours"), 0),
		SubsetTotal: parsePositive(r.PostForm.Get("subset_total"), 0), TestPath: r.PostForm.Get("test_path"), TestSHA256: r.PostForm.Get("test_sha256"),
		HostFilter: r.PostForm.Get("host_filter"), PathFilter: r.PostForm.Get("path_filter"), TagFilter: r.PostForm.Get("tag_filter"), Enabled: r.PostForm.Get("enabled") == "on"}
	if repo.ID != "" {
		old, err := s.store.GetRepository(repo.ID)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		repo.NextSubset = old.NextSubset
		if old.SubsetTotal != repo.SubsetTotal {
			repo.NextSubset = 1
		}
	}
	if err := s.store.SaveRepository(repo, r.PostForm.Get("password"), r.PostForm.Get("backend_env")); err != nil {
		s.render(w, "edit", page{Version: Version, Admin: true, CSRF: sess.CSRF, Repo: repo, Error: err.Error()})
		return
	}
	if err := s.reloadSchedule(); err != nil {
		slog.Error("scheduler reload failed", "error", err)
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) delete(w http.ResponseWriter, r *http.Request, sess session) {
	if !requireAdmin(w, sess) {
		return
	}
	id := r.PostForm.Get("id")
	if s.runner.IsActive(id) {
		http.Error(w, "Prüfung läuft", http.StatusConflict)
		return
	}
	if err := s.store.DeleteRepository(id); err != nil {
		http.Error(w, "Löschen fehlgeschlagen", 500)
		return
	}
	_ = s.reloadSchedule()
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) run(w http.ResponseWriter, r *http.Request) {
	id := r.PostForm.Get("id")
	if _, err := s.store.GetRepository(id); err != nil {
		http.NotFound(w, r)
		return
	}
	if s.runner.IsActive(id) {
		http.Error(w, "Prüfung läuft bereits", http.StatusConflict)
		return
	}
	go func() {
		if _, err := s.runner.Run(context.Background(), id, "manual"); err != nil {
			slog.Error("manual run failed", "repository_id", id, "error", err)
		}
	}()
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) webhook(w http.ResponseWriter, r *http.Request, sess session) {
	if !requireAdmin(w, sess) {
		return
	}
	value := r.PostForm.Get("webhook")
	if len(value) > 2048 || (value != "" && !strings.HasPrefix(value, "https://discord.com/api/webhooks/")) {
		http.Error(w, "Ungültiger Discord-Webhook", 400)
		return
	}
	if err := s.store.SetWebhook(value); err != nil {
		http.Error(w, "Speichern fehlgeschlagen", 500)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
