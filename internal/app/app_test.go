package app

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func testKey() string {
	return base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901"))
}

func TestStoreEncryptsSecretsAndRejectsWrongKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := OpenStore(path, testKey())
	if err != nil {
		t.Fatal(err)
	}
	r := Repository{Name: "example", Location: "/repo", Schedule: "0 3 * * *", Timezone: "UTC", MaxAgeHours: 24, SubsetTotal: 7,
		TestPath: "/marker.txt", TestSHA256: strings.Repeat("a", 64), Enabled: true}
	if err := s.SaveRepository(r, "synthetic-password", "AWS_ACCESS_KEY_ID=example-id\nAWS_SECRET_ACCESS_KEY=example-secret"); err != nil {
		t.Fatal(err)
	}
	repos, err := s.ListRepositories()
	if err != nil || len(repos) != 1 {
		t.Fatalf("repos=%v err=%v", repos, err)
	}
	pw, env, err := s.RepositorySecrets(repos[0].ID)
	if err != nil || pw != "synthetic-password" || env["AWS_SECRET_ACCESS_KEY"] != "example-secret" {
		t.Fatalf("secrets not recovered: %v", err)
	}
	var raw string
	if err := s.db.QueryRow("SELECT password_cipher FROM repositories LIMIT 1").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, "synthetic-password") {
		t.Fatal("plaintext stored")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	wrong := base64.StdEncoding.EncodeToString([]byte("abcdefghijklmnopqrstuvwxyz123456"))
	s, err = OpenStore(path, wrong)
	if err == nil {
		_ = s.Close()
		t.Fatal("wrong key accepted at startup")
	}
}

func TestRepositoryValidation(t *testing.T) {
	r := Repository{Name: "test", Location: "/repo", Schedule: "0 3 * * *", Timezone: "UTC", MaxAgeHours: 24, SubsetTotal: 7,
		TestPath: "/marker", TestSHA256: strings.Repeat("a", 64)}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	r.TestPath = "/../sensitive"
	if err := r.Validate(); err == nil {
		t.Fatal("path traversal accepted")
	}
	r.TestPath = "/marker"
	r.Schedule = "not cron"
	if err := r.Validate(); err == nil {
		t.Fatal("invalid schedule accepted")
	}
	if _, err := ParseBackendEnv("PATH=/tmp/fake"); err == nil {
		t.Fatal("unsafe environment accepted")
	}
}

func TestSelectSnapshot(t *testing.T) {
	now := time.Now().UTC()
	r := Repository{HostFilter: "host-a", TagFilter: "daily"}
	snapshots := []Snapshot{{ID: "wrong-host", Time: now, Hostname: "host-b", Tags: []string{"daily"}},
		{ID: "older", Time: now.Add(-time.Hour), Hostname: "host-a", Tags: []string{"daily"}},
		{ID: "newer", Time: now, Hostname: "host-a", Tags: []string{"daily"}}}
	selected, ok := selectSnapshot(snapshots, r)
	if !ok || selected.ID != "newer" {
		t.Fatalf("selected %+v found %v", selected, ok)
	}
}

func TestRunnerWithRealRepository(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("restic path semantics are verified in Linux CI")
	}
	if _, err := exec.LookPath("restic"); err != nil {
		t.Skip("restic is unavailable")
	}
	root := t.TempDir()
	repoPath := filepath.Join(root, "repo")
	marker := filepath.Join(root, "source", "marker.txt")
	if err := os.MkdirAll(filepath.Dir(marker), 0700); err != nil {
		t.Fatal(err)
	}
	content := []byte("restic validator integration marker\n")
	if err := os.WriteFile(marker, content, 0600); err != nil {
		t.Fatal(err)
	}
	passwordFile := filepath.Join(root, "password")
	if err := os.WriteFile(passwordFile, []byte("synthetic-password"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"-r", repoPath, "--password-file", passwordFile, "init"},
		{"-r", repoPath, "--password-file", passwordFile, "backup", marker}} {
		cmd := exec.Command("restic", args...)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("restic setup: %v: %s", err, output)
		}
	}
	s, err := OpenStore(filepath.Join(root, "state.db"), testKey())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	hash := sha256.Sum256(content)
	r := Repository{Name: "integration", Location: repoPath, Schedule: "0 3 * * *", Timezone: "UTC", MaxAgeHours: 24, SubsetTotal: 2,
		TestPath: filepath.ToSlash(marker), TestSHA256: hex.EncodeToString(hash[:]), Enabled: true}
	if err := s.SaveRepository(r, "synthetic-password", ""); err != nil {
		t.Fatal(err)
	}
	repos, err := s.ListRepositories()
	if err != nil {
		t.Fatal(err)
	}
	runner := NewRunner(s)
	for i, expected := range []string{"1/2", "2/2", "1/2"} {
		run, err := runner.Run(context.Background(), repos[0].ID, "test")
		if err != nil || run.Result != "ok" || run.Subset != expected {
			t.Fatalf("run %d: %+v err=%v", i, run, err)
		}
	}
	repos, err = s.ListRepositories()
	if err != nil {
		t.Fatal(err)
	}
	repos[0].TestSHA256 = strings.Repeat("0", 64)
	if err := s.SaveRepository(repos[0], "", ""); err != nil {
		t.Fatal(err)
	}
	run, err := runner.Run(context.Background(), repos[0].ID, "test")
	if err != nil || run.Result != "failed" || !strings.Contains(run.Error, "SHA-256") {
		t.Fatalf("hash failure not detected: %+v err=%v", run, err)
	}
	if _, err := s.GetRepository("not-found"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("unexpected lookup error: %v", err)
	}
}
