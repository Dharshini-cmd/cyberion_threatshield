# Cyberion ThreatShield

Cyberion ThreatShield is a dark SOC workspace for detection engineering, threat hunting, incident investigations, response playbooks, and MITRE ATT&CK coverage review.

## Current build

This release is a polished React + TypeScript frontend with realistic Cyberion demo data and local client-side interactions. It is intentionally free of Manus database, Manus storage, hosted authentication, and external security credentials.

The UI is designed to sit in front of a user-owned XAMPP stack. The data modules are typed and isolated in `client/src/lib/cyberionData.ts`, so a PHP/PDO API can replace the demo repository without changing the shell or page components. The API status indicator currently makes this boundary explicit: the app starts in demo mode until a local API bridge is configured.

## Run locally during development

```bash
pnpm install
pnpm dev
```

Open the Vite preview shown in the terminal.

## Build for XAMPP Apache

```bash
pnpm build
```

The static production frontend is generated in `dist/public/`. Copy the contents of that directory into a folder such as:

```text
C:/xampp/htdocs/cyberion-threatshield/
```

Start Apache from the XAMPP Control Panel and open:

```text
http://localhost/cyberion-threatshield/
```

The included `client/public/.htaccess` is copied into the production output and keeps client-side routes such as `/detections`, `/incidents`, and `/coverage` working when Apache serves the app from a subdirectory.

## Connecting a local XAMPP database later

The recommended production shape is:

- Apache serves the built frontend and a PHP API from the same subdirectory.
- PHP uses PDO with prepared statements.
- MySQL/MariaDB is managed through phpMyAdmin.
- The frontend calls relative API paths such as `/cyberion-threatshield/api/dashboard.php`.
- Database credentials remain in a local PHP configuration file outside version control.

Suggested database entities are `detection_rules`, `threat_hunts`, `hunt_evidence`, `incidents`, `incident_entities`, `incident_timeline_events`, `incident_notes`, `playbooks`, `playbook_phases`, `playbook_steps`, `attack_techniques`, and the mapping tables connecting rules/hunts to ATT&CK techniques.

For a live deployment, expose these endpoints behind Apache/PHP:

- `GET /api/health.php`
- `GET /api/dashboard.php`
- `GET|POST /api/detections.php`
- `GET|PUT /api/detections/{id}.php`
- `GET|POST /api/hunts.php`
- `GET|PUT /api/hunts/{id}.php`
- `GET|POST /api/incidents.php`
- `GET|PUT /api/incidents/{id}.php`
- `POST /api/incidents/{id}/notes.php`
- `GET /api/playbooks.php`
- `GET /api/coverage.php`

All API responses should use a consistent JSON envelope with `data`, `meta`, and `error`, and all SQL must use prepared statements. Production deployments should add authentication, authorization, CSRF protection, audit logging, HTTPS, and server-side validation.

## Workspace sections

- **Command Center:** telemetry activity, severity distribution, open investigations, activity stream, hunt queue, detection quality, and ATT&CK snapshot.
- **Detection Library:** searchable Sigma rules with severity, validation status, ATT&CK mappings, data sources, and YAML detail drawers.
- **Threat Hunts:** hypothesis cards, priorities, evidence counts, analyst ownership, and hunt states.
- **Incident Investigations:** prioritized queue with confidence, timeline drawers, analyst notes, and response actions.
- **Response Playbooks:** phase/step checklists with local progress state.
- **Coverage Matrix:** ATT&CK tactic groups with covered, partial, and gap states.

## Demo content

The dataset is clearly presented as simulated SOC content. It is intended to make the UX testable before connecting live telemetry, SIEM, EDR, ticketing, or identity systems. Do not treat it as a source of real security decisions.
