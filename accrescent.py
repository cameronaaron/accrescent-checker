#!/usr/bin/env python3

import argparse
import json
import logging
import os
import random
import signal
import sys
import time
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional

import httpx


try:
    import fcntl

    def _lock_shared(fp):
        fcntl.flock(fp.fileno(), fcntl.LOCK_SH)

    def _lock_exclusive(fp):
        fcntl.flock(fp.fileno(), fcntl.LOCK_EX)

    def _unlock(fp):
        fcntl.flock(fp.fileno(), fcntl.LOCK_UN)

except (ImportError, AttributeError):

    def _lock_shared(_):
        return None

    def _lock_exclusive(_):
        return None

    def _unlock(_):
        return None


def setup_logging(log_file: str, level: str = "INFO") -> None:
    """Set up rotating file logging with specified level."""
    root = logging.getLogger()
    if root.handlers:
        return

    Path(log_file).parent.mkdir(exist_ok=True, parents=True)

    handler = RotatingFileHandler(
        log_file,
        maxBytes=10 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))
    root.addHandler(handler)
    root.setLevel(level.upper())
    root.propagate = False


def _emit(msg: str, *, level: int = logging.INFO, quiet: bool = False) -> None:
    """Emit message to both console (if not quiet) and log."""
    if not quiet:
        print(msg)
    logging.log(level, msg)


def _atomic_json_dump(path: str, data: Any) -> None:
    """Atomically write JSON data to file with file locking."""
    Path(path).parent.mkdir(exist_ok=True, parents=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as fp:
        _lock_exclusive(fp)
        json.dump(data, fp, indent=2)
        fp.flush()
        os.fsync(fp.fileno())
        _unlock(fp)
    Path(tmp).replace(path)


def load_known_apps(path: str) -> Tuple[Dict[str, Dict[str, Any]], bool]:
    """Load known apps state from file, return (data, file_existed)."""
    if not Path(path).exists():
        return {}, False
    with open(path, encoding="utf-8") as fp:
        _lock_shared(fp)
        try:
            data: Dict[str, Dict[str, Any]] = json.load(fp)
        except json.JSONDecodeError:
            logging.error("State file corrupted; starting fresh (%s)", path)
            data = {}
        finally:
            _unlock(fp)
        return data, True


def save_known_apps(path: str, state: Dict[str, Dict[str, Any]]) -> None:
    """Save known apps state to file atomically."""
    _atomic_json_dump(path, state)


def fetch_apps(
    endpoint: str,
    client: httpx.Client,
    retries: int = 3,
    base_delay: int = 5,
    quiet: bool = False,
) -> Tuple[Dict[str, Any], Optional[int]]:
    """Fetch apps data from endpoint with exponential backoff retry."""
    delay = base_delay
    for attempt in range(1, retries + 1):
        try:
            if not quiet:
                print(f"Fetching {endpoint} (attempt {attempt}/{retries})")
            resp = client.get(endpoint)
            resp.raise_for_status()
            data = resp.json()
            if "apps" not in data:
                raise ValueError("Missing 'apps' key in response")
            return data["apps"], data.get("timestamp")
        except (httpx.TimeoutException, httpx.RequestError, ValueError, json.JSONDecodeError) as exc:
            msg = f"Error fetching apps: {exc}"
            logging.warning(msg)
            if attempt == retries:
                raise
            jitter = random.uniform(0.5, 1.5)
            sleep_time = delay * jitter
            _emit(f"{msg}. Retrying in {sleep_time:.1f}s", quiet=quiet)
            time.sleep(sleep_time)
            delay *= 2
    raise RuntimeError("Unreachable fetch error path")


def validate_app_metadata(apps: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Filter apps to only those with valid metadata."""
    good: Dict[str, Dict[str, Any]] = {}
    for pkg, meta in apps.items():
        if (
            isinstance(meta, dict)
            and meta.get("signing_cert_hashes") is not None
            and meta.get("min_version_code") is not None
        ):
            good[pkg] = meta
        else:
            logging.warning("Invalid or incomplete metadata for %s", pkg)
    return good


def diff_apps(
    old: Dict[str, Dict[str, Any]],
    new: Dict[str, Dict[str, Any]],
) -> Tuple[List[str], List[str], List[str], List[str]]:
    """Compare old and new app states, return sorted lists of changes."""
    added = sorted(set(new) - set(old))
    removed = sorted(set(old) - set(new))

    updated: List[str] = []
    cert_changed: List[str] = []

    for pkg in sorted(set(old) & set(new)):
        o, n = old[pkg], new[pkg]
        if o.get("min_version_code") != n.get("min_version_code"):
            updated.append(pkg)
        if set(o.get("signing_cert_hashes", [])) != set(n.get("signing_cert_hashes", [])):
            cert_changed.append(pkg)
    return added, removed, updated, cert_changed


def notify(
    *,
    added: List[str],
    removed: List[str],
    updated: List[str],
    cert_changed: List[str],
    old_state: Dict[str, Dict[str, Any]],
    current: Dict[str, Dict[str, Any]],
    quiet: bool,
    timestamp: Optional[int] = None,
) -> None:
    """Emit notifications for app changes."""
    if timestamp:
        now_utc = datetime.fromtimestamp(timestamp, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    else:
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    for pkg in added:
        meta = current[pkg]
        _emit(
            f"[{now_utc}] NEW    : {pkg} ({meta.get('name')}) vc={meta.get('min_version_code')}",
            quiet=quiet,
        )

    for pkg in removed:
        meta = old_state.get(pkg, {})
        _emit(
            f"[{now_utc}] REMOVED: {pkg} ({meta.get('name')}) was vc={meta.get('min_version_code')}", 
            level=logging.WARNING,
            quiet=quiet,
        )

    for pkg in updated:
        old, new = old_state[pkg], current[pkg]
        _emit(
            f"[{now_utc}] UPDATED: {pkg} ({new.get('name', old.get('name'))}) "
            f"{old.get('min_version_code')} -> {new.get('min_version_code')}",
            quiet=quiet,
        )

    for pkg in cert_changed:
        meta = current[pkg]
        _emit(
            f"[{now_utc}] CERT  : {pkg} ({meta.get('name')}) signing cert changed!",
            level=logging.WARNING,
            quiet=quiet,
        )


def print_summary(apps: Dict[str, Dict[str, Any]], quiet: bool) -> None:
    """Print repository summary on first run."""
    if quiet:
        return
    print("\nRepository summary")
    print(f"   Total apps: {len(apps)}")
    sample = list(apps.items())[:5]
    for i, (pkg, info) in enumerate(sample, 1):
        print(f"   {i}. {info.get('name')} - {pkg} (vc {info.get('min_version_code')})")
    if len(apps) > 5:
        print(f"   ... plus {len(apps) - 5} more")


class GracefulShutdown:
    """Handle graceful shutdown on SIGTERM/SIGINT."""
    def __init__(self):
        self.shutdown = False
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

    def _signal_handler(self, signum, frame):
        self.shutdown = True


def main() -> None:
    """Main application entry point."""
    parser = argparse.ArgumentParser(description="Monitor Accrescent repo for changes")
    parser.add_argument("--endpoint", default="https://repo.accrescent.app/repodata.0.json")
    parser.add_argument("--interval", type=int, default=300, help="Polling interval seconds")
    parser.add_argument("--state-file", default="known_apps.json")
    parser.add_argument("--log-file", default="app_updates.log")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--once", action="store_true", help="Run once then exit")
    parser.add_argument("--max-failures", type=int, default=5, help="Max consecutive failures before exit")
    args = parser.parse_args()

    setup_logging(args.log_file, args.log_level)

    state, file_existed = load_known_apps(args.state_file)
    first_run = not state or not file_existed

    shutdown_handler = GracefulShutdown()

    _emit(
        f"Watcher started. Endpoint={args.endpoint}, interval={args.interval}s, once={args.once}",
        quiet=args.quiet,
    )

    poll = 0
    consecutive_failures = 0
    client = httpx.Client(timeout=30.0)
    
    try:
        while not shutdown_handler.shutdown:
            poll += 1
            loop_start = time.monotonic()
            ts_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            if args.once:
                _emit(f"[{ts_utc}] Checking once", quiet=args.quiet)
            else:
                _emit(f"[{ts_utc}] Poll #{poll}", quiet=args.quiet)

            try:
                raw, repo_ts = fetch_apps(args.endpoint, client, quiet=args.quiet)
                consecutive_failures = 0
            except Exception as exc:
                consecutive_failures += 1
                logging.exception("Fetch failed - will retry next cycle")
                
                if consecutive_failures >= args.max_failures:
                    _emit(f"Max consecutive failures ({args.max_failures}) reached. Exiting.", 
                          level=logging.ERROR, quiet=args.quiet)
                    sys.exit(1)
                
                if args.once:
                    sys.exit(1)
                    
                backoff_multiplier = min(2 ** (consecutive_failures - 1), 8)
                extended_sleep = args.interval * backoff_multiplier
                jitter = random.uniform(0.8, 1.2)
                sleep_time = extended_sleep * jitter
                
                _emit(f"Will retry in {sleep_time:.1f}s (backoff due to {consecutive_failures} failures)", 
                      quiet=args.quiet)
                
                elapsed = time.monotonic() - loop_start
                remaining_sleep = max(0, sleep_time - elapsed)
                time.sleep(remaining_sleep)
                continue
            else:
                current = validate_app_metadata(raw)

                if first_run:
                    print_summary(current, args.quiet)

                added, removed, updated, cert_changed = diff_apps(state, current)

                if any((added, removed, updated, cert_changed)):
                    _emit("Changes detected", quiet=args.quiet)
                else:
                    _emit("No changes", quiet=args.quiet)

                notify(
                    added=added,
                    removed=removed,
                    updated=updated,
                    cert_changed=cert_changed,
                    old_state=state,
                    current=current,
                    quiet=args.quiet,
                    timestamp=repo_ts,
                )

                now_iso = datetime.now(timezone.utc).isoformat()
                state = {
                    pkg: {
                        "name": meta.get("name"),
                        "min_version_code": meta.get("min_version_code"),
                        "signing_cert_hashes": meta.get("signing_cert_hashes", []),
                        "last_seen": now_iso,
                        "repo_timestamp": repo_ts,
                    }
                    for pkg, meta in current.items()
                }
                save_known_apps(args.state_file, state)
                first_run = False

            if args.once:
                break

            elapsed = time.monotonic() - loop_start
            sleep_for = max(0, args.interval - elapsed)
            if not args.quiet:
                print(f"Sleeping {sleep_for:.1f}s\n")
            
            start_sleep = time.monotonic()
            while time.monotonic() - start_sleep < sleep_for:
                if shutdown_handler.shutdown:
                    break
                time.sleep(min(1.0, sleep_for - (time.monotonic() - start_sleep)))

    except KeyboardInterrupt:
        pass
    finally:
        _emit("Saving state and exiting", quiet=args.quiet)
        save_known_apps(args.state_file, state)
        client.close()


if __name__ == "__main__":
    main()
