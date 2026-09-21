# Sentinel Session Logger

Ein ressourcenschonender Audit- und Analyse-Stack für Raspberry Pi 5. Linux Audit erfasst interaktive Prozess- und Dateisystemaktivität auf dem Host. Ein Docker-Container korreliert Audit-, SSH-, Samba- und Docker-Ereignisse, speichert sie in Neon Postgres und stellt ein geschütztes Web-Dashboard bereit.

## Was erfasst wird

- Befehle interaktiver Benutzer (`auid >= 1000`), inklusive `sudo`/Privilegwechsel
- Änderungen, Umbenennungen und Löschungen in konfigurierten Samba-Verzeichnissen
- erfolgreiche und fehlgeschlagene SSH-Anmeldungen
- Samba-Aktionen mit Benutzer und Client-IP, wenn `full_audit` aktiviert ist
- Start, Stop, Kill und Entfernung von Docker-Containern
- Änderungen an Benutzer-, Gruppen-, sudo- und SSH-Konfiguration

Kernel-Audit arbeitet unterhalb von SSH und Samba und ist deshalb wesentlich belastbarer als reines Log-Scraping. Eine absolute Aufzeichnung „jeder Aktivität“ ist technisch nicht garantierbar: Prozesse können vor Aktivierung der Regeln laufen, externe Dienste können eigene Logs unterdrücken, und Datei-Lesezugriffe sind standardmäßig bewusst nicht eingeschaltet, weil sie sehr große Logmengen erzeugen. Das System zielt auf sicherheitsrelevante Benutzeraktionen.

## Architektur

```text
Linux auditd ─┐
auth.log ─────┼─ read-only mounts ─> Sentinel Collector ─> Neon Postgres
Samba logs ───┤                                      └────> Dashboard/API :8080
Docker socket ┘
```

Der Docker-Socket und `/var/log` werden nur lesbar eingebunden. Der Container besitzt keine Linux-Capabilities, hat ein schreibgeschütztes Root-Dateisystem und schreibt nur seinen Datei-Offset in das Volume `sentinel-state`.

## Raspberry Pi installieren

Voraussetzungen: Raspberry Pi OS 64-bit, Docker mit Compose-Plugin, ein vorhandenes Samba-Verzeichnis und eine Neon-Verbindungs-URL.

```bash
git clone <repository-url> session-logger
cd session-logger
cp .env.example .env
nano .env
chmod 600 .env
sudo SAMBA_PATHS=/srv/samba sh scripts/install-host-audit.sh
docker compose up -d --build
```

Danach ist das Dashboard unter `http://<raspberry-pi-ip>:8080` erreichbar. `DASHBOARD_PASSWORD` muss mindestens 12 Zeichen lang sein. Für Zugriff außerhalb des LAN sollte ein HTTPS-Reverse-Proxy oder VPN verwendet werden; Port 8080 nicht direkt ins Internet freigeben.

### Samba-Benutzernamen und Client-IP erfassen

Linux Audit sieht den Host-Prozess und die Login-UID. Für SMB-spezifische Benutzernamen und Client-IP zusätzlich den Inhalt von [config/samba-full-audit.conf.example](config/samba-full-audit.conf.example) kontrolliert in die Samba-Konfiguration übernehmen. Bei containerisiertem Samba liest Sentinel den mit `SAMBA_CONTAINER` bezeichneten Docker-Logstream. Vor dem Neustart prüfen:

Für einen bereits durch Docker Compose/Portainer verwalteten Samba-Container kann die persistente Include-Konfiguration automatisch eingerichtet werden:

```bash
sudo SAMBA_CONTAINER=samba sh scripts/configure-samba-container.sh
```

```bash
testparm
sudo systemctl restart rsyslog smbd
```

## Betrieb

```bash
docker compose ps
docker compose logs -f --tail=100
curl -u admin:<password> http://localhost:8080/healthz
sudo auditctl -l
sudo ausearch -k samba-files -ts recent
```

Der Collector beginnt beim ersten Start am Ende vorhandener Logdateien, damit keine unbegrenzte Historie importiert wird. Danach speichert er pro Datei Inode und Byte-Position und verarbeitet auch Rotationen. `RETENTION_DAYS=365` löscht täglich ältere Daten; `0` deaktiviert die automatische Löschung.

Die Speicheranzeige umfasst Heap, TOAST und Indizes der Tabelle `audit_events` (`pg_total_relation_size`). Neon-Projekt-Overhead oder andere Tabellen werden nicht als Log-Speicher ausgewiesen.

## Entwicklung und Tests

```bash
npm ci
npm test
npm run check
docker build -t session-logger:local .
```

## Grenzen und Härtung

- Das Dashboard verwendet HTTP Basic Auth. Im LAN ist HTTPS dennoch empfohlen.
- Root-Aktionen ohne vorherige Benutzeranmeldung haben keine verwertbare Login-UID und werden durch die Rauschfilterung nicht vollständig erfasst.
- Ein Host-Administrator kann Container, `auditd` oder Regeln stoppen. Manipulationssicherheit erfordert zusätzlich externes Alerting und getrennte Zugangskontrolle.
- Der Docker-Socket ist trotz read-only Mount sicherheitssensitiv. Die App sendet ausschließlich `GET /events`; für maximale Isolation kann Docker-Erfassung entfernt werden.
- Secrets gehören nur in `.env`. Zugangsdaten nach versehentlicher Veröffentlichung sofort in Raspberry Pi und Neon rotieren.

## Deinstallation der Audit-Regeln

```bash
sudo sh scripts/uninstall-host-audit.sh
docker compose down
```

Die Neon-Daten werden dadurch nicht gelöscht.
