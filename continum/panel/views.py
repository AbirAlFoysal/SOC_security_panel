import importlib
import io
import json
import re
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
MASTER_APP = REPOSITORY_ROOT / "master_app"
CONTINUM_ROOT = REPOSITORY_ROOT / "continum"
_legacy = None
_legacy_lock = threading.Lock()


def get_legacy():
    global _legacy
    with _legacy_lock:
        if _legacy is not None:
            return _legacy
        sys.path.insert(0, str(MASTER_APP))
        legacy = importlib.import_module("run")
        from project_store import ProjectStore
        from hakrawler_runner import HakrawlerRunner
        from nmap_runner import NmapRunner
        from nuclei_batch_runner import NucleiBatchRunner
        from webscan_runner import WebScanRunner
        from cli_runner import CliRunner, CONFIG as CLI_CONFIG
        from gui_apps import DesktopLauncher

        legacy.PROJECTS = ProjectStore(CONTINUM_ROOT / "projects")
        legacy.NMAP = NmapRunner(legacy.PROJECTS, legacy.locate)
        legacy.HAKRAWLER = HakrawlerRunner(legacy.PROJECTS, legacy.locate)
        legacy.WEB_SCANS = {
            tool: WebScanRunner(legacy.PROJECTS, legacy.locate, tool)
            for tool in ("sqlmap", "nikto", "nuclei")
        }
        legacy.WEB_SCANS.update({
            tool: CliRunner(legacy.PROJECTS, legacy.locate, tool)
            for tool in CLI_CONFIG
        })
        legacy.NUCLEI_BATCH = NucleiBatchRunner(legacy.PROJECTS, legacy.locate)
        legacy.DESKTOP = DesktopLauncher(CONTINUM_ROOT / ".runtime" / "desktop-tools")
        _legacy = legacy
        return legacy


def _host(value):
    value = str(value).strip()
    if not value or len(value) > 2048 or any(char.isspace() for char in value):
        return None
    candidate = value if "://" in value else "//" + value
    try:
        parsed = urlsplit(candidate)
        host = parsed.hostname
        if not host or parsed.username or parsed.password:
            return None
        return host.rstrip(".").casefold()
    except ValueError:
        return None


def _within_project_scope(project, values):
    approved = {
        host for host in (_host(project.get("host", "")), _host(project.get("ip", "")))
        if host
    }
    candidates = [line.strip() for value in values for line in str(value).splitlines()
                  if line.strip() and not line.lstrip().startswith("#")]
    return bool(approved and candidates) and all(_host(value) in approved for value in candidates)


def _scope_error(legacy, path, body):
    parts = path.split("/")
    if len(parts) < 5 or parts[1] != "api" or parts[2] != "projects":
        return None
    if "history" in parts and parts[-1] == "delete":
        return None
    ident = parts[3]
    tool = parts[4]
    data = body if isinstance(body, dict) else {}
    project = legacy.PROJECTS.get(ident)

    if tool == "nuclei_batch":
        if len(parts) > 5 and parts[5] == "cancel":
            return None
        if data.get("file_path"):
            return "Batch target files are not allowed; paste the project host/IP targets explicitly."
        targets = data.get("targets", "")
        if len(parts) > 5 and parts[5] == "resume" and not targets:
            if not re.fullmatch(r"[0-9a-f]{32}", data.get("batch_id", "")):
                return "Invalid batch session."
            state = legacy.NUCLEI_BATCH._load_state(ident, data.get("batch_id", ""))
            targets = "\n".join(host.get("url", "") for host in state.get("hosts", []))
        if not _within_project_scope(project, [targets]):
            return "Every scan target must exactly match this project's host or IP."
        return None

    if tool == "nmap":
        if len(parts) > 5 and parts[5] in ("cancel", "files"):
            return None
        command = data.get("command", "")
        try:
            _, targets, _ = legacy.NMAP.validate_command(command)
        except (ValueError, TypeError):
            return None
        if targets and not _within_project_scope(project, targets):
            return "Nmap targets must exactly match this project's host or IP."
        if not targets and command and not any(flag in command for flag in ("--help", "-h", "--version")):
            return "Specify the project's exact host or IP; target lists and resume files are not allowed."
        return None

    if tool == "hakrawler":
        if len(parts) > 5 and parts[5] in ("cancel", "files"):
            return None
        if not _within_project_scope(project, [data.get("target", "")]):
            return "Hakrawler targets must exactly match this project's host or IP."
        try:
            if "-subs" in legacy.HAKRAWLER.validate_command(data.get("command", "")):
                return "Subdomain expansion is disabled; scan only the project's exact host or IP."
        except (ValueError, TypeError):
            return None
        return None

    if tool in legacy.WEB_SCANS:
        if len(parts) > 5 and parts[5] in ("cancel", "files"):
            return None
        try:
            args = legacy.WEB_SCANS[tool].validate_command(data.get("command", ""))
        except (ValueError, TypeError):
            return None
        if tool == "sqlmap":
            target_flags = {"--url"}
            indirect_flags = {"-r", "-m", "-l", "-d", "-g", "--dork", "-c", "--openapi"}
        elif tool == "nikto":
            target_flags = {"-host", "-url"}
            indirect_flags = set()
        else:
            target_flags = {"-u"}
            indirect_flags = {"-l"}
        if any(flag in args for flag in indirect_flags):
            return "Target-list, request-file, and indirect-target modes are disabled."
        target = next((args[i + 1] for i, arg in enumerate(args[:-1]) if arg in target_flags), data.get("target", ""))
        if target == "{target}":
            target = data.get("target", "")
        utility_flags = {
            "sqlmap": {"-h", "-hh", "--hh", "--help", "--version", "--list-tampers"},
            "nikto": {"-Help", "-Version", "-list-plugins", "-dbcheck"},
            "nuclei": {"-version", "-tl", "-tgl", "-validate", "-update", "-ut"},
        }[tool]
        if target and not _within_project_scope(project, [target]) and not utility_flags.intersection(args):
            return "Scan target must exactly match this project's host or IP."
        return None

    if tool in legacy.CLI_CONFIG:
        if len(parts) > 5 and parts[5] in ("cancel", "files"):
            return None
        if tool not in ("hydra", "gobuster", "ffuf"):
            return None
        cli_runner = importlib.import_module("cli_runner")
        try:
            mode, parsed = cli_runner.parse_parts(tool, data.get("command", ""))
        except (ValueError, TypeError):
            return None
        target_flags = {
            "hydra": set(),
            "gobuster": {"--url", "--domain", "--server"},
            "ffuf": {"-u"},
        }[tool]
        if tool == "ffuf" and any(
            part.get("option", {}).get("flag") == "-request" for part in parsed
        ):
            return "HTTP request-file scans are disabled; use the project's exact host or IP."
        targets = [
            part.get("value", "") for part in parsed
            if part.get("option", {}).get("flag") in target_flags
        ]
        if tool == "hydra":
            targets.extend(part["positional"] for part in parsed if "positional" in part)
        if not targets:
            targets = [data.get("target", "")]
        if tool == "gobuster" and mode in ("s3", "gcs", "tftp", "dns"):
            return "This workspace only allows scans against the project's exact host or IP."
        if not _within_project_scope(project, targets):
            return "Scan target must exactly match this project's host or IP."
    return None


def _response_from_legacy(request, legacy):
    handler = object.__new__(legacy.Handler)
    handler.path = request.get_full_path()
    handler.headers = request.headers
    try:
        port = urlsplit("//" + request.headers.get("Host", "")).port
    except ValueError:
        port = None
    handler.server = SimpleNamespace(server_port=port or int(request.get_port() or 8000))
    handler.rfile = io.BytesIO(request.body)
    handler.wfile = io.BytesIO()
    status = {"value": 200}
    headers = {}
    handler.send_response = lambda code, *args: status.update(value=code)
    handler.send_header = lambda name, value: headers.__setitem__(name, value)
    handler.end_headers = lambda: None
    handler.log_message = lambda *args: None
    if request.method == "GET":
        handler.do_GET()
    elif request.method == "POST":
        handler.do_POST()
    else:
        return HttpResponse(status=405)
    response = HttpResponse(handler.wfile.getvalue(), status=status["value"])
    for name, value in headers.items():
        if name.lower() not in ("content-length", "connection", "transfer-encoding"):
            response[name] = value
    return response


@csrf_exempt
def legacy_app(request):
    if request.path == "/continum-mode.js":
        return HttpResponse("window.CONTINUM_MODE = true;", content_type="text/javascript")
    legacy = get_legacy()
    if request.method == "POST" and request.path.startswith("/api/projects/"):
        if request.headers.get("X-App-Token") != legacy.TOKEN:
            return JsonResponse({"error": "Request must come from this app."}, status=403)
        try:
            body = json.loads(request.body)
            message = _scope_error(legacy, request.path, body)
        except (AttributeError, FileNotFoundError, KeyError, OSError, TypeError, ValueError):
            message = None
        if message:
            return JsonResponse({"error": message}, status=403)

    response = _response_from_legacy(request, legacy)
    if request.path == "/" and response.status_code == 200 and "text/html" in response.get("Content-Type", ""):
        content = response.content.decode("utf-8")
        content = content.replace(
            "<head>",
            '<head><link rel="stylesheet" href="/static/panel/tailwind.css">'
            '<script src="/continum-mode.js" defer></script>',
            1,
        )
        content = content.replace("<body>", '<body class="min-h-screen bg-slate-950 text-slate-100">', 1)
        content = content.replace(
            '<span id="network-updated" class="network-updated"></span>',
            '<button id="network-refresh" class="network-updated" type="button" '
            'aria-label="Refresh network status">Refresh status</button>'
            '<span id="network-updated" class="network-updated"></span>',
            1,
        )
        content = content.replace(
            '<div id="tools" class="tools" aria-live="polite">',
            '<button id="tool-refresh" class="secondary" type="button" '
            'aria-label="Refresh installed tool status">Refresh tool status</button>'
            '<div id="tools" class="tools" aria-live="polite">',
            1,
        )
        response.content = content.encode("utf-8")
    return response
