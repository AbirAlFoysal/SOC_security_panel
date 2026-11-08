# SOC_security_panel

Local cybersecurity workspace built with Python 3 and a browser interface.

## Run

```sh
make run
```

Runs the Django-based Continum workspace at http://127.0.0.1:8000. Use
`make run PORT=8080` for a different port. Run `make run-legacy` to start the
original application with its development auto-reload.

## Features

- Project creation, searchable history, custom statuses, notes, and saved documents
- Command workspaces for Nmap, Hakrawler, SQLmap, Nikto, tcpdump, Hydra, John the Ripper, Hashcat, Gobuster, ffuf, and Aircrack-ng
- Searchable parameter panels, global presets, project-specific history, live output, and downloadable result files
- Desktop launch buttons for Wireshark and Burp Suite
- Installed-tool detection and package management
- AnonSurf and MAC changer controls with live network status

Application dependencies use the Python standard library. Security tools are installed separately; network controls require Linux and desktop authentication.

Assessment data and personal presets stay in `projects/` inside this checkout and are excluded from Git. Existing third-party tool collections and archives are also excluded.

## Checks

```sh
python3 -m unittest discover -s master_app/tests
```

Optional browser command-builder regression checks (Node.js is only needed for this check):

```sh
node master_app/tests/workspace_builder.test.js
```

See [application documentation](master_app/README.md) for platform support and detailed usage.

## Django alternative

The parallel Django-served workspace lives in [continum/](continum/). It uses
the repository-root `.venv`, keeps its data under `continum/projects/`, and
reuses the existing UI and tool runners without moving the original app. See
[Continum setup instructions](continum/README.md) for startup and tests.
