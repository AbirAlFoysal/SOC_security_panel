# SOC_security_panel

Local cybersecurity workspace built with Python 3 and a browser interface.

## Run

```sh
make run
```

Opens http://127.0.0.1:8000 with automatic reload during development. Use `make run PORT=8080` for a different port.

## Features

- Project creation, searchable history, custom statuses, notes, and saved documents
- Nmap and Hakrawler command builders, parameter reference panels, global presets, and project-specific scan histories
- Desktop launch buttons for Wireshark and Burp Suite
- Installed-tool detection and package management
- AnonSurf and MAC changer controls with live network status

Application dependencies use the Python standard library. Security tools are installed separately; network controls require Linux and desktop authentication.

Assessment data and personal presets stay in `projects/` inside this checkout and are excluded from Git. Existing third-party tool collections and archives are also excluded.

## Checks

```sh
python3 -m unittest discover -s master_app/tests
```

See [application documentation](master_app/README.md) for platform support and detailed usage.
