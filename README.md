# SOC_security_panel

Local cybersecurity workspace built with Python 3 and a browser interface.

## Run

```sh
make run
```

Opens http://127.0.0.1:8000 with automatic reload during development. Use `make run PORT=8080` for a different port.

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
