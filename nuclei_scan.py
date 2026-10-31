#!/usr/bin/env python3
"""
Nuclei Batch Scanner with Resume + WAF detection
- Resume: `python nuclei_scan.py resume`
- Distinguishes clean scans from WAF-blocked incomplete scans via coverage %
- State saved per-run in .progress.json (atomic, throttled)
"""

import csv
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
import multiprocessing as mp
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
import shutil
import traceback

# ----------------- Configuration -----------------
MAX_WORKERS      = 7          # 8GB RAM safe
NUCLEI_TIMEOUT   = 900        # 15 min hard cap per target
SIGTERM_GRACE    = 10
TEMPLATE_TAGS    = "cve,tech,panel,exposure,misconfiguration,default-login"
SEVERITY         = "critical,high,medium"
RATE_LIMIT       = 15         # per worker; 4 workers = 60 RPS total — WAF-safe
NUCLEI_C         = 5          # template concurrency
NUCLEI_BS        = 5          # bulk size
MAX_HOST_ERROR   = 30         # abort scan after N errors on the host
STATS_INTERVAL   = 30
STATE_FILE       = ".progress.json"
STATE_SAVE_EVERY = 10
LARGE_SCAN_WARN  = 200
# Coverage thresholds
CLEAN_COVERAGE_MIN = 70       # >= 70% requests → trustworthy NO_FINDINGS
WAF_ERROR_RATE     = 0.10     # >= 10% errors → suspect WAF blocking
# -------------------------------------------------


def log(msg):
    print(msg, flush=True)


def find_nuclei():
    p = shutil.which("nuclei")
    if not p:
        log("[!] Nuclei not found in PATH.")
        sys.exit(1)
    return p


def read_urls_from_csv(path):
    urls = []
    with open(path, newline="", encoding="utf-8-sig") as f:
        for row in csv.reader(f):
            if not row:
                continue
            v = row[0].strip().strip('"').strip("'")
            if v and not v.startswith("#"):
                urls.append(v)
    return urls


def normalize_url(u):
    u = u.strip()
    if not u:
        return None
    if not u.lower().startswith(("http://", "https://")):
        u = "https://" + u
    p = urlparse(u)
    if not p.netloc:
        return None
    return u


def safe_name(u, i):
    p = urlparse(u)
    b = (p.netloc or p.path).replace(":", "_").replace("/", "_")
    b = "".join(c for c in b if c.isalnum() or c in ("-", "_", "."))
    return f"{i:03d}_{b or 'target'}"


def _terminate(proc):
    if proc.poll() is not None:
        return
    try:
        proc.send_signal(signal.SIGTERM)
    except Exception:
        pass
    try:
        proc.wait(timeout=SIGTERM_GRACE)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        proc.kill()
        proc.wait(timeout=5)
    except Exception:
        pass


def parse_coverage(log_path):
    """
    Parse the LAST stats line in the .log to get:
      (pct, errors, requests_done, requests_total, gave_up)
    gave_up = True if Nuclei reported max-host-error abort.
    """
    pct = 0
    errors = 0
    done = 0
    total = 0
    gave_up = False
    try:
        with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                # Track max-host-error abort message
                if "max-host-error" in line.lower() or "giving up" in line.lower():
                    gave_up = True
                if "Requests:" not in line or "Errors:" not in line:
                    continue
                try:
                    # Errors
                    err_part = line.split("Errors:")[1].split("|")[0].strip()
                    errors = int(err_part)
                    # Requests: 526/13905 (3%)
                    req_part = line.split("Requests:")[1].strip()
                    frac, pct_part = req_part.split("(")
                    done_s, total_s = frac.strip().split("/")
                    done = int(done_s.strip())
                    total = int(total_s.strip())
                    pct = int(pct_part.split("%")[0].strip())
                except Exception:
                    continue
    except Exception:
        pass
    return pct, errors, done, total, gave_up


def run_nuclei(args):
    nuclei_path, url, final_jsonl, final_log, timeout = args
    name = Path(final_jsonl).stem

    tmp_jsonl = Path(tempfile.gettempdir()) / f"nuclei_{name}_{os.getpid()}.jsonl"
    tmp_log   = Path(tempfile.gettempdir()) / f"nuclei_{name}_{os.getpid()}.log"

    for p in (tmp_jsonl, tmp_log):
        try:
            if p.exists(): p.unlink()
        except Exception:
            pass

    cmd = [
        nuclei_path,
        "-u", url,
        "-tags", TEMPLATE_TAGS,
        "-severity", SEVERITY,
        "-jsonl-export", str(tmp_jsonl),
        "-silent",
        "-nc",
        "-no-interactsh",
        "-timeout", "10",
        "-retries", "1",
        "-rate-limit", str(RATE_LIMIT),
        "-c", str(NUCLEI_C),
        "-bs", str(NUCLEI_BS),
        "-ss", "host-spray",
        "-max-host-error", str(MAX_HOST_ERROR),
        "-stats",
        "-stats-interval", str(STATS_INTERVAL),
    ]

    timed_out = False
    rc = None
    detail = ""

    try:
        with open(tmp_log, "wb") as lf:
            proc = subprocess.Popen(
                cmd,
                stdout=lf,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            try:
                rc = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                except Exception:
                    _terminate(proc)
                try:
                    rc = proc.wait(timeout=SIGTERM_GRACE)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    except Exception:
                        proc.kill()
                    try:
                        rc = proc.wait(timeout=5)
                    except Exception:
                        rc = -9
    except FileNotFoundError:
        return (url, "ERROR", final_jsonl, final_log, "nuclei binary not found", 0)
    except Exception as e:
        return (url, "ERROR", final_jsonl, final_log, f"{type(e).__name__}: {e}", 0)

    jsonl_ok = tmp_jsonl.exists() and tmp_jsonl.stat().st_size > 0
    log_ok   = tmp_log.exists() and tmp_log.stat().st_size > 0

    if jsonl_ok:
        try:
            shutil.move(str(tmp_jsonl), final_jsonl)
        except Exception as e:
            detail = (detail + f" | move jsonl error: {e}").strip(" |")
    if log_ok:
        try:
            shutil.move(str(tmp_log), final_log)
        except Exception as e:
            detail = (detail + f" | move log error: {e}").strip(" |")

    # Parse coverage from the moved log
    pct = 0
    errs = 0
    done_req = 0
    total_req = 0
    gave_up = False
    if log_ok:
        pct, errs, done_req, total_req, gave_up = parse_coverage(final_log)

    # ---- Classification ----
    error_rate = (errs / done_req) if done_req > 0 else 0.0

    if jsonl_ok and timed_out:
        status = "FINDINGS_PARTIAL"
        detail = f"partial findings (timeout) | {pct}% coverage, {errs} errs"
    elif jsonl_ok:
        status = "FINDINGS"
        detail = f"{pct}% coverage"
    elif timed_out:
        status = "TIMEOUT"
        detail = f"exceeded {timeout}s | {pct}% coverage, {errs} errs"
    elif not log_ok:
        status = "ERROR"
        detail = "no output produced"
    elif gave_up and pct < CLEAN_COVERAGE_MIN:
        # Nuclei gave up because of max-host-error
        status = "INCOMPLETE_WAF"
        detail = f"aborted by max-host-error | {pct}% coverage, {errs} errs ({int(error_rate*100)}%)"
    elif pct < CLEAN_COVERAGE_MIN:
        # Scan ended early for some reason
        status = "INCOMPLETE_WAF"
        detail = f"{pct}% coverage, {errs} errs"
    elif error_rate >= WAF_ERROR_RATE:
        # Completed-ish but too many errors to be trustworthy
        status = "INCOMPLETE_WAF"
        detail = f"{pct}% coverage but {int(error_rate*100)}% error rate"
    else:
        # Genuinely clean
        status = "NO_FINDINGS"
        detail = f"{pct}% coverage, {errs} errs"

    if rc is not None and rc not in (0, None) and status not in ("FINDINGS", "FINDINGS_PARTIAL"):
        detail = (detail + f" | nuclei exit={rc}").strip(" |")

    for p in (tmp_jsonl, tmp_log):
        try:
            if p.exists(): p.unlink()
        except Exception:
            pass

    return (url, status, final_jsonl, final_log, detail, pct)


def read_first_findings(jsonl_path, n=2):
    out = []
    try:
        with open(jsonl_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    info = obj.get("info", {})
                    out.append((info.get("severity", "?"), info.get("name", "unknown")))
                except Exception:
                    continue
                if len(out) >= n:
                    break
    except Exception:
        pass
    return out


def load_state(folder):
    sf = Path(folder) / STATE_FILE
    if sf.exists():
        try:
            with open(sf, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {"completed": [], "results": []}


def save_state(folder, state):
    sf = Path(folder) / STATE_FILE
    tmp = Path(str(sf) + ".tmp")
    try:
        with open(tmp, "w") as f:
            json.dump(state, f, indent=2)
        os.replace(tmp, sf)
    except Exception as e:
        log(f"[!] Failed to save state: {e}")


def format_eta(seconds):
    if seconds <= 0 or seconds == float("inf"):
        return "unknown"
    seconds = int(seconds)
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h > 0:
        return f"{h}h{m:02d}m"
    return f"{m}m{s:02d}s"


def confirm_large_scan(n):
    if n <= LARGE_SCAN_WARN:
        return True
    worst = n * NUCLEI_TIMEOUT // MAX_WORKERS
    realistic = n * 60 // MAX_WORKERS
    log(f"[!] Large scan: {n} targets")
    log(f"    Worst case (all timeout): {format_eta(worst)}")
    log(f"    Realistic estimate:       {format_eta(realistic)}")
    resp = input("Continue? [y/N]: ").strip().lower()
    return resp == "y"


def run_scan(nuclei_path, valid_urls, out_dir, existing_state=None, is_resume=False):
    results = existing_state.get("results", []) if existing_state else []

    if not is_resume:
        log(f"[*] Output: {out_dir}")
        log(f"[*] Templates: {TEMPLATE_TAGS} | Severity: {SEVERITY}")
        log(f"[*] Workers: {MAX_WORKERS} | Timeout: {NUCLEI_TIMEOUT}s")
        log(f"[*] Rate limit: {RATE_LIMIT}/s per worker | Max host errors: {MAX_HOST_ERROR}")

    jobs = []
    for i, url in enumerate(valid_urls, start=1):
        name = safe_name(url, i)
        jobs.append((
            nuclei_path, url,
            str(out_dir / f"{name}.jsonl"),
            str(out_dir / f"{name}.log"),
            NUCLEI_TIMEOUT,
        ))

    start_time = time.time()
    total = len(jobs)
    log(f"[*] Launching pool ({MAX_WORKERS} workers, {total} targets)...")

    completed_urls = set(existing_state.get("completed", [])) if existing_state else set()
    completions_since_save = 0

    try:
        with mp.Pool(processes=MAX_WORKERS) as pool:
            for idx, r in enumerate(pool.imap_unordered(run_nuclei, jobs), start=1):
                url, status, jf, lf, det, pct = r
                elapsed = time.time() - start_time
                throughput = idx / elapsed if elapsed > 0 else 0
                remaining = total - idx
                eta_sec = remaining / throughput if throughput > 0 else 0

                log(
                    f"[{idx}/{total}] {status:<18} {url}   "
                    f"({det}) | ETA {format_eta(eta_sec)}"
                )

                # store as tuple for state (drop extra pct field for json)
                results.append((url, status, jf, lf, det))
                completed_urls.add(url)
                completions_since_save += 1

                if completions_since_save >= STATE_SAVE_EVERY or idx == total:
                    save_state(out_dir, {
                        "completed": list(completed_urls),
                        "results": results,
                    })
                    completions_since_save = 0

    except Exception:
        log("[!] Pool error:")
        traceback.print_exc()
        save_state(out_dir, {"completed": list(completed_urls), "results": results})

    # ---- Final summary ----
    findings          = [r for r in results if r[1] == "FINDINGS"]
    findings_partial  = [r for r in results if r[1] == "FINDINGS_PARTIAL"]
    no_finding        = [r for r in results if r[1] == "NO_FINDINGS"]
    incomplete_waf    = [r for r in results if r[1] == "INCOMPLETE_WAF"]
    timed_out         = [r for r in results if r[1] == "TIMEOUT"]
    errors            = [r for r in results if r[1] == "ERROR"]
    total_time = time.time() - start_time

    log("\n===== SUMMARY =====")
    log(f"Scanned this session          : {len(jobs)}")
    log(f"  Findings (complete)         : {len(findings)}")
    log(f"  Findings (partial)          : {len(findings_partial)}")
    log(f"  No findings (trustworthy)   : {len(no_finding)}")
    log(f"  Incomplete (WAF-blocked)    : {len(incomplete_waf)}")
    log(f"  Timed out                   : {len(timed_out)}")
    log(f"  Errors                      : {len(errors)}")
    log(f"Total wall time               : {int(total_time // 60)}m{int(total_time % 60):02d}s")

    # Write summary.txt
    summary_path = out_dir / "summary.txt"
    try:
        with open(summary_path, "w", encoding="utf-8") as f:
            f.write(f"Nuclei scan — {datetime.now().isoformat()}\n")
            f.write(f"Templates: {TEMPLATE_TAGS}\n")
            f.write(f"Severity: {SEVERITY}\n")
            f.write(f"Workers: {MAX_WORKERS} | Timeout: {NUCLEI_TIMEOUT}s\n")
            f.write(f"Rate limit: {RATE_LIMIT}/s | Max host errors: {MAX_HOST_ERROR}\n\n")
            f.write(f"FINDINGS           : {len(findings)}\n")
            f.write(f"FINDINGS_PARTIAL   : {len(findings_partial)}\n")
            f.write(f"NO_FINDINGS        : {len(no_finding)}\n")
            f.write(f"INCOMPLETE_WAF     : {len(incomplete_waf)}\n")
            f.write(f"TIMEOUT            : {len(timed_out)}\n")
            f.write(f"ERROR              : {len(errors)}\n\n")
            f.write("STATUS\tURL\tJSONL\tLOG\tDETAIL\n")
            for url, status, jf, lf, det in sorted(results, key=lambda r: r[1]):
                f.write(f"{status}\t{url}\t{jf}\t{lf}\t{det}\n")
        log(f"[*] Summary written: {summary_path}")
    except Exception as e:
        log(f"[!] Failed to write summary: {e}")

    if results:
        preview_targets = (findings + findings_partial)[:10]
        if preview_targets:
            log(f"\n[*] Findings preview (first {len(preview_targets)}):")
            for url, status, jf, _, _ in preview_targets:
                preview = read_first_findings(jf, n=2)
                if preview:
                    log(f"  {url}:")
                    for sev, nm in preview:
                        log(f"    - [{sev:<8}] {nm}")


def resume_mode(nuclei_path):
    log("[*] Resume mode selected.")
    report_dirs = sorted(Path(".").glob("nuclei_reports_*"), reverse=True)
    if not report_dirs:
        log("[!] No previous report folders found.")
        return

    log("[*] Available report folders:")
    for i, d in enumerate(report_dirs):
        sf = d / STATE_FILE
        if sf.exists():
            try:
                state = load_state(d)
                done = len(state.get("completed", []))
                status = f"Resumable ({done} done)"
            except Exception:
                status = "Resumable"
        else:
            status = "No state file"
        log(f"  [{i}] {d.name} ({status})")

    try:
        choice = int(input("Select folder index to resume: ").strip())
        folder = report_dirs[choice]
    except (ValueError, IndexError):
        log("[!] Invalid selection.")
        return

    state = load_state(folder)
    completed = set(state.get("completed", []))
    log(f"[*] Resuming folder: {folder}")
    log(f"[*] Already completed: {len(completed)} targets")

    csv_path = input("Enter path to original CSV file again: ").strip()
    csv_path = os.path.expanduser(csv_path.strip('"').strip("'"))
    if not os.path.isfile(csv_path):
        log(f"[!] File not found: {csv_path}")
        return

    raw_urls = read_urls_from_csv(csv_path)
    valid = [n for n in (normalize_url(u) for u in raw_urls) if n]
    remaining = [u for u in valid if u not in completed]
    log(f"[*] Remaining targets to scan: {len(remaining)}")

    if not remaining:
        log("[*] All targets in this CSV already completed.")
        return

    if not confirm_large_scan(len(remaining)):
        log("[*] Aborted.")
        return

    run_scan(nuclei_path, remaining, folder, state, is_resume=True)


def main():
    log("[*] Nuclei batch scanner starting.")

    if len(sys.argv) > 1 and sys.argv[1].lower() == "resume":
        nuclei_path = find_nuclei()
        resume_mode(nuclei_path)
        return

    raw = input("Enter path to the CSV file (single column of URLs, no header): ").strip()
    csv_path = os.path.expanduser(raw.strip('"').strip("'"))
    log(f"[*] CSV: {csv_path}")

    if not os.path.isfile(csv_path):
        log(f"[!] File not found: {csv_path}")
        sys.exit(1)

    nuclei_path = find_nuclei()
    log(f"[*] Nuclei: {nuclei_path}")

    raw_urls = read_urls_from_csv(csv_path)
    log(f"[*] Raw entries: {len(raw_urls)}")

    valid, invalid = [], []
    for u in raw_urls:
        n = normalize_url(u)
        if n is None:
            invalid.append((u, "invalid/empty URL"))
        else:
            valid.append(n)

    log(f"[*] Valid targets: {len(valid)} | Invalid: {len(invalid)}")
    if not valid:
        log("[!] No valid URLs to scan.")
        sys.exit(1)

    if not confirm_large_scan(len(valid)):
        log("[*] Aborted.")
        sys.exit(0)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = Path(f"nuclei_reports_{timestamp}").resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    save_state(out_dir, {"completed": [], "results": []})
    run_scan(nuclei_path, valid, out_dir)


if __name__ == "__main__":
    mp.freeze_support()
    try:
        main()
    except KeyboardInterrupt:
        log("\n[!] Interrupted by user.")
        sys.exit(130)
    except SystemExit:
        raise
    except Exception:
        log("[!] Unhandled exception:")
        traceback.print_exc()
        sys.exit(1)
