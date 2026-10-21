# Restic Backup Validator

Version 1.0 prüft mehrere [restic](https://restic.net/)-Repositories in einem Go-basierten Docker-Container. Sie beantwortet drei Fragen: Gibt es einen aktuellen Snapshot? Ist das Repository einschließlich eines rotierenden Teils der Daten lesbar? Lässt sich eine festgelegte Datei mit dem erwarteten SHA-256-Hash wiederherstellen? Fehler lösen einen Discord-Alarm aus. Die Web-Oberfläche ist durch OIDC geschützt.

## Voraussetzungen

- Docker Compose und ein bestehender HTTPS-Reverse-Proxy
- Ein OIDC-Provider mit einer Gruppe `backup_admin` im ID-Token (Claim-Name konfigurierbar)
- Bestehende restic-Repositories und deren Passwörter
- OpenSSL zur Generierung des lokalen Verschlüsselungsschlüssels

Der Container erstellt keine Backups und repariert keine Repositories. Er ruft nur `snapshots`, `check` und `restore` auf. Die geplante Prüfung läuft intern; `run-once` ist für systemd-Timer oder Cron verfügbar. Beide Betriebsarten sollten nicht gleichzeitig für dasselbe Repository eingeplant werden.

## Einrichtung

1. `.env.example` nach `.env` kopieren. Den Wert von `APP_MASTER_KEY` mit `openssl rand -base64 32` erzeugen und eintragen. `.env` nie committen oder als Docker-Build-Argument verwenden.
2. Beim OIDC-Provider einen vertraulichen Web-Client mit Redirect-URI `https://DEINE-DOMAIN/callback` anlegen. `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` und gegebenenfalls `OIDC_GROUP_CLAIM` in `.env` setzen. `OIDC_ISSUER` ist genau der `issuer`-Wert aus dem Discovery-Dokument, **nicht** dessen URL mit `/.well-known/openid-configuration`; die App ergänzt diesen Pfad selbst. Der Gruppen-Claim muss den Wert `backup_admin` für Administratoren enthalten.
3. `APP_URL` auf die öffentliche HTTPS-Origin setzen. Den Reverse Proxy auf `127.0.0.1:8080` routen und TLS aktivieren. Der Container-Port wird im Compose-Beispiel ausschließlich auf Loopback veröffentlicht.
4. `docker compose up -d --build` startet eine lokale Instanz. In der Web-Oberfläche als Mitglied von `backup_admin` anmelden, Repositories und den Discord-Webhook eintragen. Der Webhook wird nach dem Speichern nicht mehr angezeigt.
5. Für jedes Repository einen Snapshot-Pfad und SHA-256-Hash einer stabilen Testdatei eintragen. Bei Linux-Backups muss der Pfad so aussehen, wie `restic ls <snapshot-id>` ihn ausgibt. Den Hash mit `sha256sum <testdatei>` ermitteln. Eine Änderung der Testdatei erfordert eine Anpassung des erwarteten Hashes.

Die Web-Oberfläche erlaubt jedem Konto des eingestellten OIDC-Providers die Ansicht und manuelle Prüfstarts. Nur `backup_admin` darf Konfiguration und Secrets bearbeiten. Entfallene Gruppenrechte werden spätestens mit dem Ablauf der 30-minütigen Anwendungssitzung wirksam. OIDC-Login benötigt ausgehenden HTTPS-Zugang zum Provider.

Meldet der Start bei der OIDC Discovery einen 404-Fehler und enthält die angeforderte URL `/.well-known/openid-configuration` zweimal, wurde die Discovery-URL statt der Issuer-URL in `OIDC_ISSUER` eingetragen. Im Discovery-Dokument des Providers den Wert des Feldes `issuer` ablesen, exakt diesen Wert in `.env` eintragen und den Container mit `docker compose up -d --force-recreate validator` neu erstellen. Ein bloßer Neustart übernimmt Änderungen an der Compose-Umgebung nicht zuverlässig.

## Repositories und Zugangsdaten

Ein Repository erhält einen Namen, restic-Adresse, Passwort, Cron-Ausdruck mit fünf Feldern, IANA-Zeitzone, maximales Snapshot-Alter, Anzahl der Teile, Testdateipfad und erwarteten SHA-256-Hash. Host, Snapshot-Pfad und Tag können die Auswahl des neuesten Snapshots eingrenzen. Ein Zeitplan `0 3 * * *` startet täglich um 03:00 Uhr in der eingestellten Zeitzone.

Backend-Zugangsdaten können als `KEY=WERT`-Zeilen im Web erfasst werden. Unterstützt werden die Umgebungsvariablen-Präfixe `AWS_`, `B2_`, `AZURE_`, `GOOGLE_` und `RCLONE_`. Der Container enthält restic, rclone und OpenSSH; bei Backends mit Dateien müssen Konfigurations- und Schlüsseldateien separat geschützt in den Container gemountet werden. Solche Mounts gehören nicht in das Git-Repository. Das Repository-Passwort und die eingegebenen Backend-Variablen werden in SQLite verschlüsselt. Repository-Adressen dürfen keine Zugangsdaten enthalten.

Lokale Repositories brauchen einen **schreibbaren** Mount, da restic für Prüfungen Repository-Locks anlegt. Der Validator ruft keine löschenden restic-Befehle auf. Für Remote-Backends müssen die Zugangsdaten ebenfalls Lock-Operationen erlauben.

Die rotierende Datenprüfung verwendet `--read-data-subset=n/t` und erhöht `n` nach erfolgreichem `check`; nach `t` beginnt sie wieder bei 1. Ein fehlgeschlagener Teil wird beim nächsten Lauf wiederholt. Der Test-Restore nutzt die ID des zuvor ausgewählten Snapshots und einen temporären Ordner auf dem Container-Tmpfs. Der Lauf speichert Startzeit, Dauer, Ergebnis, Fehler und einen separaten Discord-Zustellfehler in SQLite und gibt eine kurze strukturierte Statuszeile an Docker-Logs aus. Eine Discord-Nachricht wird bei jedem fehlgeschlagenen Prüflauf gesendet.

## Schutz und Wiederherstellung

`APP_MASTER_KEY` ist ein Base64-kodierter 32-Byte-Schlüssel. Die App verschlüsselt Secrets mit AES-256-GCM und verweigert beim Start einen Schlüssel, der nicht zur bestehenden Datenbank passt. Die `.env` liegt getrennt von SQLite und muss mit restriktiven Host-Dateirechten geschützt werden. Sie ist kein Schutz gegen einen Angreifer mit Docker- oder Host-Admin-Rechten. Die Datenbank und **genau der dazugehörige Schlüssel** müssen getrennt gesichert werden; ohne Schlüssel können die gespeicherten Zugangsdaten nicht wiederhergestellt werden. Ein Schlüsselwechsel erfordert eine geplante Migration und ist in Version 1.0 nicht als Web-Aktion verfügbar.

Im mitgelieferten Compose-Beispiel liegt die Datenbank im Volume `validator-data`; ein eigener Bind-Mount kann dieses ersetzen. Ein Backup sollte bei gestopptem Container oder mit der SQLite-Backup-API erstellt werden. Die Web-App setzt sichere Cookies, CSRF-Schutz und Sicherheitsheader. Der Reverse Proxy muss HTTPS bereitstellen und darf den App-Port nicht öffentlich freigeben. Der OIDC-Provider sollte MFA verlangen. Die Health-Route `/healthz` gibt keine Repository-Daten aus.

### Datenbank: `permission denied`

Der Container läuft als UID/GID `10001:10001`. Meldet der Start `open /data/validator.db: permission denied`, sind das gemountete Verzeichnis oder die SQLite-Dateien für diesen Benutzer möglicherweise nicht schreibbar. Das kann insbesondere nach einem Wechsel von einem früheren Container oder einer Wiederherstellung auftreten. Die Rechte aus dem Dockerfile gelten nicht für den Inhalt eines Mounts.

Zuerst den tatsächlichen Mount-Typ und Host-Pfad ermitteln. Die Ausgabe enthält bei einem Bind-Mount einen lokalen Host-Pfad; sie nicht in öffentliche Fehlermeldungen kopieren.

```sh
docker inspect "$(docker compose ps -q validator)" --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Type}} {{.Source}} -> {{.Destination}} writable={{.RW}}{{end}}{{end}}'
```

**Bind-Mount:** Den ausgegebenen Host-Pfad anstelle von `/PFAD/ZUM/VALIDATOR-DATENVERZEICHNIS` einsetzen. Vor der Rechteänderung prüfen, dass es das dedizierte Datenverzeichnis des Validators ist, und eine Sicherung der Datenbank erstellen. Den Container anhalten; `-wal` und `-shm` können Teil des aktuellen SQLite-Zustands sein und dürfen nicht gelöscht werden. Bei einer üblichen rootful-Docker-Installation ohne User-Namespace-Remapping:

```sh
set -e
docker compose stop validator
DATA_DIR='/PFAD/ZUM/VALIDATOR-DATENVERZEICHNIS'
sudo chown 10001:10001 "$DATA_DIR"
sudo chmod 700 "$DATA_DIR"
for file in "$DATA_DIR/validator.db" "$DATA_DIR/validator.db-wal" "$DATA_DIR/validator.db-shm"; do
  if [ -e "$file" ]; then
    sudo chown 10001:10001 "$file"
    sudo chmod 600 "$file"
  fi
done
docker compose up -d validator
docker compose logs --tail=30 validator
```

**Benanntes Volume:** Das unveränderte Compose-Beispiel dieses Repositories verwendet `validator-data`. Dafür die Rechte mit einem einmaligen Hilfscontainer korrigieren:

```sh
set -e
docker compose stop validator
docker compose run --rm --no-deps --user 0:0 --cap-add CHOWN --entrypoint /bin/sh validator -ec '
  chown 10001:10001 /data
  chmod 700 /data
  for file in /data/validator.db /data/validator.db-wal /data/validator.db-shm; do
    if [ -e "$file" ]; then
      chown 10001:10001 "$file"
      chmod 600 "$file"
    fi
  done
'
docker compose up -d validator
docker compose logs --tail=30 validator
```

Falls der Fehler danach bleibt, die Rechte und ACLs des Host-Pfads, einen schreibgeschützten Mount, das Host-Dateisystem und Docker-User-Namespace-Remapping prüfen. Bei aktiviertem Remapping oder rootless Docker kann die Container-UID `10001` einer anderen Host-UID entsprechen. Das Datenverzeichnis und die Datenbank nicht löschen oder durch eine leere Datei ersetzen.

## `run-once` mit systemd oder Cron

`docker compose run --rm validator run-once` prüft alle konfigurierten Repositories einmal und liefert bei einem Fehler Exitcode 1. Für einen externen Zeitplan die interne Automatik der Repositories deaktivieren. Ergebnisse werden in derselben Datenbank gespeichert.

## Entwicklung und Veröffentlichung

Jede Funktion wird auf einem Feature-Branch entwickelt und nur durch einen Pull Request in `main` integriert. PR-CI testet Go-Code und scannt Dateien sowie Git-Historie auf Secrets. Die lokale Pre-Push-Sperre wird mit `git config --local core.hooksPath .githooks` aktiviert. Vor dem ersten öffentlichen Push und jedem PR müssen `node scripts/check-secrets.mjs --tracked --history`, `go test ./...`, `go vet ./...` und ein Review aller ausgehenden Commits bestehen. Auch Dokumentation und Beispiele sind öffentlich.

Ein Merge erstellt **kein** Release und veröffentlicht **kein** Docker-Image. Nur `Cyberhunter88` startet in GitHub Actions den Workflow **Manual release and Docker build** auf `main` und gibt zum Beispiel `v1.0.0` ein. Der Workflow prüft Version, Tests und Secret-Scan erneut, baut `linux/amd64` und `linux/arm64`, veröffentlicht `ghcr.io/cyberhunter88/restic-backup-validator:v1.0.0` und `ghcr.io/cyberhunter88/restic-backup-validator:latest` mit demselben Digest, prüft beide Tags und erstellt erst dann das GitHub Release. Beim Fehler wird kein GitHub Release erstellt; ein bereits hochgeladenes Image muss vor einem erneuten Lauf geprüft werden. GHCR-Pakete sind bei der ersten Veröffentlichung standardmäßig privat; falls das Image öffentlich abrufbar sein soll, muss der Eigentümer seine Sichtbarkeit danach in den Paketeinstellungen auf „Public“ ändern.

GitHub Secret Scanning und Push Protection ergänzen den lokalen Scan. Kein Scanner garantiert, dass jedes denkbare Secret erkannt wird. Echte Zugangsdaten gehören ausschließlich in `.env`, geschützte Mounts oder die verschlüsselte Web-Konfiguration.
