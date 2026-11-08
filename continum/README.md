# Continum

Continum is a Django-served, separate local workspace alongside the original
application. The existing `projects/` data has been copied into
`continum/projects/`; the original data remains unchanged. New Continum data
is stored separately and is not synchronized back to the legacy app.

The existing UI and scan runners are reused for feature parity; Django provides
the application entry point and local API boundary. Tailwind utilities are built
locally and added to the existing interface.

## Run locally

From the repository root, `make run` starts Continum on
`http://127.0.0.1:8000`. To start it directly:

```sh
python3 -m venv .venv  # create only if the repository has no .venv yet
.venv/bin/python -m pip install -r continum/requirements.txt
cd continum
npm install
npm run build:css
../.venv/bin/python manage.py runserver 127.0.0.1:8001
```

Open <http://127.0.0.1:8001>. Keep the server bound to localhost. Continum uses
the copied project history and scan outputs in its own `projects/` directory.

Scan requests are restricted to the exact host or IP saved on the project.
Subdomains, target lists from files, request-file modes, and other indirect
targets are rejected. Tool installation, desktop launchers, project records,
notes, documents, scan history, and output downloads use the existing
implementation. Idle pages do not poll continuously; use the visible refresh
controls to update status, including while a tool or system operation is
running. Status updates are requested only on page load, after an action, or
when a refresh control is used.

## Check

```sh
cd continum
../.venv/bin/python manage.py test
npm run build:css
```
