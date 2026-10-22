# Cybersecurity startscreen

Run `make run` from the parent folder. Python 3 is the only app dependency.
The app opens at http://127.0.0.1:8000. Stop with Ctrl+C; use `make run PORT=8080` for another port.
Auto reload is enabled by `make run`: HTML/CSS/JavaScript edits refresh the browser within about a second; Python edits restart the server and reconnect the browser. Reload/restart waits until active tool operations finish. If an edit introduces a Python syntax error, fix it and save again; the watcher stays running.

The left side is reserved and empty. A narrow list on the right checks 12 configured tools, marks detected executables with a green tick and missing tools with a cross. Each three-dot menu provides Install, Update, and Remove. Bulk actions install missing tools or update installed tools from this list. Output appears below the list when an operation runs. Failures do not stop the remaining bulk operations.

Detection is for the server computer, using PATH plus common user and system binary directories; it is not a full inventory of every program on disk. A detected executable does not guarantee the tool's runtime dependencies or permissions are configured.

Linux uses APT, DNF, or Pacman. APT checks repository availability and package ownership before update/removal. Hakrawler uses its official Go module for installations outside APT; Go must already be installed. Existing binaries in the normal Go directory or the user's ~/.local/bin can be managed. Other custom installations report that they require their original installer. AnonSurf needs a configured package source for installation/update.

Windows uses WinGet for configured native packages (Nmap and Wireshark), and Go for Hakrawler. Other listed tools report unsupported native installation; use their official instructions or WSL. Linux-only tools cannot all be installed natively on Windows. Windows and alternate Linux distributions have not been tested on real machines.

Administrator commands use the Linux desktop authentication dialog through pkexec, with noninteractive sudo as a fallback. The app never collects passwords. On Windows, native installers may show UAC prompts. APT actions use the existing repository cache; refresh stale repository metadata using the OS package tools if needed.

The server binds only to localhost and restricts commands to the configured tools/actions. Package mutations require a same-app request token and reject cross-origin requests. Do not expose this server through a reverse proxy or run it as root.

Checks: `python3 -m unittest discover -s master_app/tests -v` and `node --check master_app/app.js` (Node is optional, for checking JavaScript only).


## Project workspaces

Start project opens a form for name, IP address, host name, other details, and status. At least a valid IP or a host name is required. Add custom statuses from this form or the project overview. Project history lists saved projects and supports searching by name, target, and status.

All project data is stored in the repository's `projects/` folder (beside `Makefile`), never in a separate Documents folder or browser local storage. Each project has a generated ID folder with `project.json`, `notes.md`, and `docs/`. Global custom statuses are stored in `projects/statuses.json`. Back up this folder to retain your work.

The full project workspace has an editable overview, Notes with an explicit Save button, and Saved docs with upload/download (4 MB per document). Under Tools, clicking a tool name opens its workspace. Only the separate right-side arrow expands History. Nmap supports actual scans; other tool execution interfaces will be added later. Histories are project-specific.


## Network navigation

The top nav is available on the startscreen and in project workspaces. AnonSurf shows actual routing state, Tor service state, and DNS state; MAC changer shows the selected active interface and its current MAC. Status refreshes every two seconds. Missing binaries display Not installed. Controls currently require Linux; MAC changes additionally require a NetworkManager Wi-Fi/Ethernet connection, iproute2, and systemd.

Start AnonSurf runs AnonSurf independently. Start MAC changer uses the existing root helper to save the current connection settings, randomize the MAC, and reconnect. Restore MAC restores those saved settings. Stop AnonSurf before changing or restoring the MAC. Administrator actions use the system authentication dialog; passwords are not entered into the app. Network actions may briefly interrupt connectivity. The app does not turn either tool on automatically.

The root helper keeps its original recovery state in /var/lib/desktop-anon and publishes only the managed interface name in /run/desktop-anon-status.json for the unprivileged status reader. This runtime network state is separate from project data. The existing `make anon` / `make stop anon` commands remain available.

New projects are saved immediately before opening their workspace, and the startscreen history refreshes after creation. Duplicate IP/domain targets return a choice: Continue existing opens the selected original without modifying it; Make a copy creates an independent project with the submitted details. Domain comparisons ignore case, trailing dots, and URL scheme/path; IP comparisons normalize IPv4/IPv6 notation. No DNS resolution is performed to infer domain-to-IP matches.


## Nmap workspace

Nmap opens a compact Zenmap-style workspace with Target, Preset, an editable command field, and adjacent Scan/Stop buttons. The right-hand parameter panel provides searchable flags, readable names, hover descriptions, and prompts for values or files. Available profiles are Regular, Quick, Service detection, All TCP ports, and Host discovery. Built-in TCP presets use connect mode. Raw-packet options such as SYN scans prompt for administrator authentication on Linux. Commands are parsed into recognized Nmap arguments and never passed through a shell; targets can include hosts, networks, or target lists. Nmap reports incompatible combinations in its output.

The Nmap Output, Ports / Hosts, Host Details, and Scans tabs show live output and structured XML results. Finished, failed, and cancelled scans are saved automatically to the project's history. Raw text and XML files stay under `projects/<id>/scans/nmap/`; the latest 256 KB of terminal output is included in project metadata. History entries reopen the saved result. One scan runs at a time, with a 30-minute limit. Package/network mutations and development restarts wait until a scan ends.


## Parameters, presets, and input files

The reference panel contains documented Nmap scan, discovery, port, version, script, OS, timing, packet, output, and miscellaneous options. Click to add/remove a flag. Value-taking options open a dialog. File-based options (including target lists, exclusion lists, script arguments, and custom databases) offer a file picker; directory options offer directory selection. Installed NSE names/categories can be entered directly, or a script file/directory can be uploaded. Uploads stay inside `projects/<id>/nmap-inputs/`; up to 200 files and 4 MB total are accepted per selection. For larger local datasets, enter an existing path on the server computer.

The + button at the right end of the command field saves a named preset to `projects/nmap-presets.json`. It appears in the Preset dropdown and survives restarts. The current target becomes a reusable `{target}` placeholder. Duplicate preset names are rejected. TCP scan techniques, timing templates, and port selectors replace conflicting selections within their group. The full command remains editable.

Output-file options are redirected into this project's scan directory, including output paths embedded in resume files. Privileged scans use a helper with a cancellation marker and time limit, so Stop works after elevation. The global network navbar stays pinned while scrolling every page.


## Per-project scan history

Every Nmap run is registered in its project's history immediately on start and updated in place when it completes, fails, or is cancelled. Open Tools → Nmap's right-side arrow → History for the saved scan list. Click an entry to reopen its results. Each row has a trash icon with a confirmation dialog; deleting it removes that scan's metadata and generated text/XML/export files only. A running scan must be stopped first. Presets remain global across all projects and are not deleted with scan history.


## Hakrawler workspace

Hakrawler now has the same compact command builder, parameter sidebar, preset saving, and project history flow as Nmap. Its 14 native options are listed with descriptions and value prompts. Target URLs are supplied through stdin using the separate multiline target field or URL-list file loader; the command field contains only the actual Hakrawler executable and options. The built-in presets use JSON output for structured URLs and source details. You can also select ordinary text output options and read raw output.

Crawl/Stop controls, live output, discovered-URL and source tables, and saved crawl selection are available in the workspace. Each crawl is registered immediately in `tool_history.hakrawler`, with raw output and input URLs saved in `projects/<id>/scans/hakrawler/`. Repeated command titles get numeric suffixes, independently of Nmap history. History rows can reopen results or delete a completed crawl. Global Hakrawler presets live in `projects/hakrawler-presets.json`, separate from global Nmap presets.

MAC changer and AnonSurf are omitted from the startscreen toolkit and project tool sidebar; their existing navbar controls remain. Only one scan/crawl/system mutation runs at a time, and auto reload waits for it to finish.


## Desktop applications

Wireshark and Burp Suite have launch-only project pages: Open Wireshark or Open Burp Suite. GUI tools do not have history dropdowns. Missing installations display Not installed and disable the launcher. Detection checks PATH and common native installer locations. Applications launch as the desktop user without a shell or administrator elevation. A running instance started by this app is reused. Startup errors are reported in the page, with launch logs under `.runtime/desktop-tools/`. These buttons launch the installed desktop application; they do not embed its interface into the browser or start a packet capture automatically.


## SQLmap and Nikto

Open either tool from the project sidebar to prepare a command. Scan and Stop sit
next to the preset selector. Search the right-hand parameter panel by flag or name;
hover for descriptions and click to add or remove an option. Options accepting
files offer an upload or an existing local path. SQLmap accepts full URLs with query
parameters, POST data, request files, and target lists. Nikto accepts web service
URLs (including ports) or a host-list file.

The command's + button saves a global preset. URL targets use `{target}` so the
preset follows the selected project. Input-file paths remain tied to their original
local files. Scan output streams into the Output tab, and every run is saved under
that project's tool history with command-based titles. The tool's right-side
sidebar arrow opens its History link without opening the tool page. History entries
can be reopened or deleted. SQLmap session/report files and Nikto output stay in
`projects/<id>/scans/<tool>/`; deleting a history entry also removes its generated
files. SQLmap session files supplied through `-s` are copied before use.

Installed status is detected on this machine. Install missing tools using the
startscreen tool menu. Browser scans run without interactive terminal prompts
(SQLmap `--batch`, Nikto `-nointeractive`); terminal/GUI shell modes must be used
outside this workspace. Runs stop after 30 minutes and save partial output.

The bundled parameter catalogs come from the official [SQLmap command parser](https://github.com/sqlmapproject/sqlmap/blob/master/lib/parse/cmdline.py)
and [Nikto option reference](https://github.com/sullo/nikto/wiki/Annotated-Option-List),
retrieved October 23, 2026. Options added in a newer upstream release may require
updating this catalog; older installed releases may reject newer options.
