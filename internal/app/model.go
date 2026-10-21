package app

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/robfig/cron/v3"
)

const Version = "1.0.1"

type Repository struct {
	ID            string
	Name          string
	Location      string
	Schedule      string
	Timezone      string
	MaxAgeHours   int
	SubsetTotal   int
	NextSubset    int
	TestPath      string
	TestSHA256    string
	HostFilter    string
	PathFilter    string
	TagFilter     string
	Enabled       bool
	HasPassword   bool
	HasBackendEnv bool
}

type Run struct {
	ID                string
	RepoID            string
	Started           time.Time
	DurationMS        int64
	Result            string
	Error             string
	SnapshotID        string
	Subset            string
	Trigger           string
	NotificationError string
}

type Snapshot struct {
	ID       string    `json:"id"`
	Time     time.Time `json:"time"`
	Hostname string    `json:"hostname"`
	Paths    []string  `json:"paths"`
	Tags     []string  `json:"tags"`
}

var hexHash = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
var envKey = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
var urlCredentials = regexp.MustCompile(`://[^/@]+:[^/@]+@`)

func (r Repository) Validate() error {
	if strings.TrimSpace(r.Name) == "" || len(r.Name) > 100 {
		return errors.New("Name muss 1 bis 100 Zeichen enthalten")
	}
	if strings.TrimSpace(r.Location) == "" || len(r.Location) > 2048 {
		return errors.New("Repository-Adresse fehlt oder ist zu lang")
	}
	if u, err := url.Parse(r.Location); err == nil && u.User != nil {
		return errors.New("Zugangsdaten dürfen nicht in der Repository-Adresse stehen")
	}
	if urlCredentials.MatchString(r.Location) || strings.ContainsAny(r.Location, "?#") {
		return errors.New("Repository-Adresse darf keine eingebetteten Zugangsdaten oder URL-Parameter enthalten")
	}
	if r.MaxAgeHours < 1 || r.MaxAgeHours > 8760 {
		return errors.New("Snapshot-Grenzwert muss zwischen 1 und 8760 Stunden liegen")
	}
	if r.SubsetTotal < 1 || r.SubsetTotal > 365 {
		return errors.New("Anzahl der Daten-Teile muss zwischen 1 und 365 liegen")
	}
	if !strings.HasPrefix(r.TestPath, "/") || strings.Contains(r.TestPath, "..") || len(r.TestPath) > 1024 {
		return errors.New("Testdatei braucht einen absoluten Pfad ohne '..'")
	}
	if !hexHash.MatchString(r.TestSHA256) {
		return errors.New("SHA-256 muss 64 Hex-Zeichen enthalten")
	}
	if _, err := time.LoadLocation(r.Timezone); err != nil {
		return fmt.Errorf("ungültige Zeitzone: %w", err)
	}
	if _, err := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow).Parse(r.Schedule); err != nil {
		return fmt.Errorf("ungültiger Cron-Zeitplan: %w", err)
	}
	return nil
}

func ParseBackendEnv(input string) (map[string]string, error) {
	result := make(map[string]string)
	if len(input) > 16384 {
		return nil, errors.New("Backend-Umgebung ist zu groß")
	}
	for _, line := range strings.Split(input, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || !envKey.MatchString(key) || strings.ContainsRune(value, 0) {
			return nil, errors.New("Backend-Variablen müssen KEY=WERT-Zeilen sein")
		}
		if !(strings.HasPrefix(key, "AWS_") || strings.HasPrefix(key, "B2_") || strings.HasPrefix(key, "AZURE_") || strings.HasPrefix(key, "GOOGLE_") || strings.HasPrefix(key, "RCLONE_")) {
			return nil, errors.New("Backend-Variable mit nicht erlaubtem Präfix: " + key)
		}
		if key == "RCLONE_CONFIG" || key == "RCLONE_CONFIG_PASS" {
			return nil, errors.New("Rclone-Konfigurationspfade werden nur als read-only Mount unterstützt")
		}
		result[key] = value
	}
	return result, nil
}

func parsePositive(s string, fallback int) int {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		return fallback
	}
	return n
}
