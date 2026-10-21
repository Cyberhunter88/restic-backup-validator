package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Runner struct {
	store  *Store
	mu     sync.Mutex
	active map[string]bool
	client *http.Client
}

func NewRunner(store *Store) *Runner {
	return &Runner{store: store, active: make(map[string]bool), client: &http.Client{Timeout: 10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (x *Runner) start(id string) bool {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.active[id] {
		return false
	}
	x.active[id] = true
	return true
}

func (x *Runner) finish(id string) {
	x.mu.Lock()
	delete(x.active, id)
	x.mu.Unlock()
}

func (x *Runner) IsActive(id string) bool {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.active[id]
}

func (x *Runner) Run(ctx context.Context, id, trigger string) (Run, error) {
	if !x.start(id) {
		return Run{}, errors.New("Prüfung läuft bereits")
	}
	defer x.finish(id)
	repo, err := x.store.GetRepository(id)
	if err != nil {
		return Run{}, err
	}
	runID, err := NewID()
	if err != nil {
		return Run{}, err
	}
	run := Run{ID: runID, RepoID: id, Started: time.Now().UTC(), Trigger: trigger, Result: "failed"}
	var findings []string
	password, backendEnv, err := x.store.RepositorySecrets(id)
	if err != nil {
		findings = append(findings, "Zugangsdaten konnten nicht gelesen werden")
	}
	if err == nil {
		workdir, tempErr := os.MkdirTemp("", "restic-validator-")
		if tempErr != nil {
			findings = append(findings, "Temporäres Verzeichnis konnte nicht erstellt werden")
		} else {
			defer os.RemoveAll(workdir)
			_ = os.Chmod(workdir, 0700)
			passwordFile := filepath.Join(workdir, "password")
			if writeErr := os.WriteFile(passwordFile, []byte(password), 0600); writeErr != nil {
				findings = append(findings, "Passwortdatei konnte nicht angelegt werden")
			} else {
				var snapshots []Snapshot
				output, runErr := restic(ctx, repo, backendEnv, passwordFile, "snapshots", "--json")
				if runErr != nil {
					findings = append(findings, "Snapshot-Abfrage: "+redact(output, password, backendEnv))
				} else if jsonErr := json.Unmarshal([]byte(output), &snapshots); jsonErr != nil {
					findings = append(findings, "Snapshot-Daten sind ungültig")
				} else {
					selected, found := selectSnapshot(snapshots, repo)
					if !found {
						findings = append(findings, "Kein passender Snapshot vorhanden")
					} else {
						run.SnapshotID = selected.ID
						if selected.Time.After(time.Now().Add(5*time.Minute)) || time.Since(selected.Time) > time.Duration(repo.MaxAgeHours)*time.Hour {
							findings = append(findings, "Neuester Snapshot liegt außerhalb des erlaubten Alters")
						}
					}
				}
				subset := repo.NextSubset
				if subset < 1 || subset > repo.SubsetTotal {
					subset = 1
				}
				run.Subset = fmt.Sprintf("%d/%d", subset, repo.SubsetTotal)
				checkOutput, checkErr := restic(ctx, repo, backendEnv, passwordFile, "check", "--read-data-subset="+run.Subset)
				if checkErr != nil {
					findings = append(findings, "Integritätsprüfung: "+redact(checkOutput, password, backendEnv))
				} else if advanceErr := x.store.AdvanceSubset(id, subset, repo.SubsetTotal); advanceErr != nil {
					findings = append(findings, "Rotationsstand konnte nicht gespeichert werden")
				}
				if run.SnapshotID != "" {
					target := filepath.Join(workdir, "restore")
					restoreOutput, restoreErr := restic(ctx, repo, backendEnv, passwordFile, "restore", run.SnapshotID, "--target", target, "--include", repo.TestPath)
					if restoreErr != nil {
						findings = append(findings, "Test-Wiederherstellung: "+redact(restoreOutput, password, backendEnv))
					} else if verifyErr := verifyRestoredFile(target, repo.TestPath, repo.TestSHA256); verifyErr != nil {
						findings = append(findings, "Test-Wiederherstellung: "+verifyErr.Error())
					}
				}
			}
		}
	}
	if len(findings) == 0 {
		run.Result = "ok"
	}
	run.Error = strings.Join(findings, "; ")
	run.DurationMS = time.Since(run.Started).Milliseconds()
	if err := x.store.SaveRun(run); err != nil {
		return run, err
	}
	slog.Info("validation finished", "repository_id", id, "result", run.Result, "duration_ms", run.DurationMS, "run_id", run.ID)
	if run.Result != "ok" {
		run.NotificationError = x.notify(repo, run)
		if run.NotificationError != "" {
			_ = x.store.SetNotificationError(run.ID, run.NotificationError)
			slog.Warn("discord alert not delivered", "run_id", run.ID, "reason", run.NotificationError)
		}
	}
	return run, nil
}

type cappedBuffer struct {
	bytes.Buffer
	max int
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if b.Len() < b.max {
		_, _ = b.Buffer.Write(p[:min(len(p), b.max-b.Len())])
	}
	return len(p), nil
}

func restic(parent context.Context, r Repository, env map[string]string, passwordFile string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(parent, 4*time.Hour)
	defer cancel()
	argv := append([]string{"-r", r.Location, "--password-file", passwordFile}, args...)
	cmd := exec.CommandContext(ctx, "restic", argv...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "TMPDIR=" + filepath.Dir(passwordFile), "RESTIC_CACHE_DIR=" + filepath.Join(filepath.Dir(passwordFile), "cache")}
	for key, value := range env {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	stdout := &cappedBuffer{max: 4 * 1024 * 1024}
	stderr := &cappedBuffer{max: 64 * 1024}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		return "Prüfschritt hat das Zeitlimit überschritten", ctx.Err()
	}
	if err != nil {
		return strings.TrimSpace(stderr.String() + "\n" + stdout.String()), err
	}
	return stdout.String(), nil
}

func selectSnapshot(snapshots []Snapshot, r Repository) (Snapshot, bool) {
	var matches []Snapshot
	for _, s := range snapshots {
		if r.HostFilter != "" && s.Hostname != r.HostFilter {
			continue
		}
		if r.PathFilter != "" {
			found := false
			for _, p := range s.Paths {
				if p == r.PathFilter {
					found = true
				}
			}
			if !found {
				continue
			}
		}
		if r.TagFilter != "" {
			found := false
			for _, t := range s.Tags {
				if t == r.TagFilter {
					found = true
				}
			}
			if !found {
				continue
			}
		}
		matches = append(matches, s)
	}
	if len(matches) == 0 {
		return Snapshot{}, false
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].Time.After(matches[j].Time) })
	return matches[0], true
}

func verifyRestoredFile(root, path, expected string) error {
	rel := strings.TrimPrefix(path, "/")
	parts := strings.Split(rel, "/")
	current := root
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return errors.New("ungültiger Testdateipfad")
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return errors.New("Testdatei fehlt im Snapshot")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("symbolischer Link ist als Testdatei nicht erlaubt")
		}
	}
	f, err := os.Open(current)
	if err != nil {
		return errors.New("Testdatei ist nicht lesbar")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("Testdatei ist keine reguläre Datei")
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return errors.New("Testdatei konnte nicht gelesen werden")
	}
	if hex.EncodeToString(h.Sum(nil)) != strings.ToLower(expected) {
		return errors.New("SHA-256 der Testdatei stimmt nicht überein")
	}
	return nil
}

func redact(output, password string, env map[string]string) string {
	output = strings.TrimSpace(output)
	for _, value := range env {
		if value != "" {
			output = strings.ReplaceAll(output, value, "[REDACTED]")
		}
	}
	if password != "" {
		output = strings.ReplaceAll(output, password, "[REDACTED]")
	}
	if len(output) > 2048 {
		output = output[:2048] + "…"
	}
	if output == "" {
		return "restic fehlgeschlagen"
	}
	return output
}

func (x *Runner) notify(repo Repository, run Run) string {
	webhook, err := x.store.Webhook()
	if err != nil {
		return "Discord-Webhook konnte nicht entschlüsselt werden"
	}
	if webhook == "" {
		return "Discord-Webhook ist nicht konfiguriert"
	}
	message := fmt.Sprintf("Restic-Prüfung fehlgeschlagen: %s (%s)\n%s", repo.Name, run.Started.Format(time.RFC3339), run.Error)
	if len(message) > 1800 {
		message = message[:1800] + "…"
	}
	data, _ := json.Marshal(map[string]any{"content": message, "allowed_mentions": map[string]any{"parse": []string{}}})
	for attempt := 0; attempt < 3; attempt++ {
		req, err := http.NewRequest(http.MethodPost, webhook, bytes.NewReader(data))
		if err != nil {
			return "Discord-Anfrage konnte nicht erstellt werden"
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := x.client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return ""
			}
			if resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode < 500 {
				return fmt.Sprintf("Discord antwortete mit HTTP %d", resp.StatusCode)
			}
		}
		if attempt < 2 {
			time.Sleep(time.Duration(1<<attempt) * time.Second)
		}
	}
	return "Discord-Zustellung nach drei Versuchen fehlgeschlagen"
}
