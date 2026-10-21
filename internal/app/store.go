package app

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db   *sql.DB
	aead cipher.AEAD
}

func OpenStore(path, masterKey string) (*Store, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(masterKey))
	if err != nil || len(key) != 32 {
		return nil, errors.New("APP_MASTER_KEY muss ein Base64-kodierter 32-Byte-Schlüssel sein")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	_ = f.Close()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, statement := range []string{
		"PRAGMA busy_timeout=5000",
		"PRAGMA journal_mode=WAL",
		`CREATE TABLE IF NOT EXISTS repositories (
		 id TEXT PRIMARY KEY, name TEXT NOT NULL, location TEXT NOT NULL, schedule TEXT NOT NULL,
		 timezone TEXT NOT NULL, max_age_hours INTEGER NOT NULL, subset_total INTEGER NOT NULL,
		 next_subset INTEGER NOT NULL DEFAULT 1, test_path TEXT NOT NULL, test_sha256 TEXT NOT NULL,
		 host_filter TEXT NOT NULL, path_filter TEXT NOT NULL, tag_filter TEXT NOT NULL,
		 enabled INTEGER NOT NULL, password_cipher TEXT NOT NULL, env_cipher TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS runs (
		 id TEXT PRIMARY KEY, repo_id TEXT NOT NULL, started TEXT NOT NULL, duration_ms INTEGER NOT NULL,
		 result TEXT NOT NULL, error TEXT NOT NULL, snapshot_id TEXT NOT NULL, subset TEXT NOT NULL,
		 trigger TEXT NOT NULL, notification_error TEXT NOT NULL DEFAULT '')`,
		"CREATE INDEX IF NOT EXISTS runs_repo_started ON runs(repo_id, started DESC)",
		"CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
	} {
		if _, err := db.Exec(statement); err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	return &Store{db: db, aead: aead}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) seal(plaintext string, associated string) (string, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := s.aead.Seal(nonce, nonce, []byte(plaintext), []byte(associated))
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (s *Store) open(encoded string, associated string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(data) < s.aead.NonceSize() {
		return "", errors.New("gespeichertes Secret ist beschädigt")
	}
	plaintext, err := s.aead.Open(nil, data[:s.aead.NonceSize()], data[s.aead.NonceSize():], []byte(associated))
	if err != nil {
		return "", errors.New("Secret kann mit diesem Schlüssel nicht entschlüsselt werden")
	}
	return string(plaintext), nil
}

func NewID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func (s *Store) ListRepositories() ([]Repository, error) {
	rows, err := s.db.Query(`SELECT id,name,location,schedule,timezone,max_age_hours,subset_total,next_subset,
	 test_path,test_sha256,host_filter,path_filter,tag_filter,enabled,password_cipher,env_cipher
	 FROM repositories ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Repository
	for rows.Next() {
		var r Repository
		var enabled int
		var pw, env string
		if err := rows.Scan(&r.ID, &r.Name, &r.Location, &r.Schedule, &r.Timezone, &r.MaxAgeHours, &r.SubsetTotal, &r.NextSubset,
			&r.TestPath, &r.TestSHA256, &r.HostFilter, &r.PathFilter, &r.TagFilter, &enabled, &pw, &env); err != nil {
			return nil, err
		}
		r.Enabled, r.HasPassword, r.HasBackendEnv = enabled == 1, pw != "", env != ""
		result = append(result, r)
	}
	return result, rows.Err()
}

func (s *Store) GetRepository(id string) (Repository, error) {
	repos, err := s.ListRepositories()
	if err != nil {
		return Repository{}, err
	}
	for _, r := range repos {
		if r.ID == id {
			return r, nil
		}
	}
	return Repository{}, sql.ErrNoRows
}

func (s *Store) SaveRepository(r Repository, password, backendInput string) error {
	if err := r.Validate(); err != nil {
		return err
	}
	var oldPassword, oldEnv string
	if r.ID == "" {
		id, err := NewID()
		if err != nil {
			return err
		}
		r.ID = id
	} else {
		_ = s.db.QueryRow("SELECT password_cipher,env_cipher FROM repositories WHERE id=?", r.ID).Scan(&oldPassword, &oldEnv)
	}
	if password == "" && oldPassword == "" {
		return errors.New("Repository-Passwort fehlt")
	}
	if password != "" {
		sealed, err := s.seal(password, r.ID+":password")
		if err != nil {
			return err
		}
		oldPassword = sealed
	}
	if backendInput != "" {
		env, err := ParseBackendEnv(backendInput)
		if err != nil {
			return err
		}
		data, err := json.Marshal(env)
		if err != nil {
			return err
		}
		sealed, err := s.seal(string(data), r.ID+":env")
		if err != nil {
			return err
		}
		oldEnv = sealed
	}
	if r.NextSubset < 1 || r.NextSubset > r.SubsetTotal {
		r.NextSubset = 1
	}
	_, err := s.db.Exec(`INSERT INTO repositories (id,name,location,schedule,timezone,max_age_hours,subset_total,next_subset,
	 test_path,test_sha256,host_filter,path_filter,tag_filter,enabled,password_cipher,env_cipher)
	 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
	 name=excluded.name,location=excluded.location,schedule=excluded.schedule,timezone=excluded.timezone,
	 max_age_hours=excluded.max_age_hours,subset_total=excluded.subset_total,
	 next_subset=CASE WHEN repositories.subset_total<>excluded.subset_total THEN 1 ELSE repositories.next_subset END,
	 test_path=excluded.test_path,test_sha256=excluded.test_sha256,host_filter=excluded.host_filter,
	 path_filter=excluded.path_filter,tag_filter=excluded.tag_filter,enabled=excluded.enabled,
	 password_cipher=excluded.password_cipher,env_cipher=excluded.env_cipher`,
		r.ID, r.Name, r.Location, r.Schedule, r.Timezone, r.MaxAgeHours, r.SubsetTotal, r.NextSubset,
		r.TestPath, strings.ToLower(r.TestSHA256), r.HostFilter, r.PathFilter, r.TagFilter, r.Enabled, oldPassword, oldEnv)
	return err
}

func (s *Store) RepositorySecrets(id string) (string, map[string]string, error) {
	var pw, env string
	if err := s.db.QueryRow("SELECT password_cipher,env_cipher FROM repositories WHERE id=?", id).Scan(&pw, &env); err != nil {
		return "", nil, err
	}
	password, err := s.open(pw, id+":password")
	if err != nil {
		return "", nil, err
	}
	result := map[string]string{}
	if env != "" {
		plaintext, err := s.open(env, id+":env")
		if err != nil {
			return "", nil, err
		}
		if err := json.Unmarshal([]byte(plaintext), &result); err != nil {
			return "", nil, err
		}
	}
	return password, result, nil
}

func (s *Store) DeleteRepository(id string) error {
	_, err := s.db.Exec("DELETE FROM repositories WHERE id=?", id)
	return err
}

func (s *Store) AdvanceSubset(id string, current, total int) error {
	next := current + 1
	if next > total {
		next = 1
	}
	_, err := s.db.Exec("UPDATE repositories SET next_subset=? WHERE id=? AND next_subset=?", next, id, current)
	return err
}

func (s *Store) SaveRun(r Run) error {
	_, err := s.db.Exec(`INSERT INTO runs(id,repo_id,started,duration_ms,result,error,snapshot_id,subset,trigger,notification_error)
	 VALUES(?,?,?,?,?,?,?,?,?,?)`, r.ID, r.RepoID, r.Started.UTC().Format("2006-01-02T15:04:05.000000000Z07:00"), r.DurationMS, r.Result, r.Error, r.SnapshotID, r.Subset, r.Trigger, r.NotificationError)
	return err
}

func (s *Store) SetNotificationError(id, message string) error {
	_, err := s.db.Exec("UPDATE runs SET notification_error=? WHERE id=?", message, id)
	return err
}

func (s *Store) ListRuns(repoID string, limit int) ([]Run, error) {
	if limit < 1 || limit > 500 {
		limit = 100
	}
	query := "SELECT id,repo_id,started,duration_ms,result,error,snapshot_id,subset,trigger,notification_error FROM runs"
	args := []any{}
	if repoID != "" {
		query += " WHERE repo_id=?"
		args = append(args, repoID)
	}
	query += " ORDER BY started DESC LIMIT ?"
	args = append(args, limit)
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Run
	for rows.Next() {
		var r Run
		var started string
		if err := rows.Scan(&r.ID, &r.RepoID, &started, &r.DurationMS, &r.Result, &r.Error, &r.SnapshotID, &r.Subset, &r.Trigger, &r.NotificationError); err != nil {
			return nil, err
		}
		r.Started, _ = timeParse(started)
		result = append(result, r)
	}
	return result, rows.Err()
}

func timeParse(value string) (time.Time, error) {
	return time.Parse("2006-01-02T15:04:05.000000000Z07:00", value)
}

func (s *Store) SetWebhook(value string) error {
	sealed, err := s.seal(value, "settings:discord")
	if err != nil {
		return err
	}
	_, err = s.db.Exec("INSERT INTO settings(key,value) VALUES('discord',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", sealed)
	return err
}

func (s *Store) Webhook() (string, error) {
	var encoded string
	err := s.db.QueryRow("SELECT value FROM settings WHERE key='discord'").Scan(&encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("Webhook kann nicht gelesen werden: %w", err)
	}
	return s.open(encoded, "settings:discord")
}
