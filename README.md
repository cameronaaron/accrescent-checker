# Accrescent Repo Watcher

This script monitors the [Accrescent](https://accrescent.app) repository for changes in app metadata, such as new apps, removals, updates, and signing certificate changes. It is designed to run periodically or as a one-shot check, logging and printing notifications about repository changes.

## Features

- Polls the Accrescent repository for app metadata at a configurable interval.
- Detects and reports:
  - New apps
  - Removed apps
  - Updated apps (version code changes)
  - Apps with changed signing certificates
- Logs all activity to a rotating log file.
- Maintains a local state file to track known apps.
- Handles graceful shutdown on SIGINT/SIGTERM.
- Supports exponential backoff on repeated failures.

## Requirements

- Python 3.7+
- [httpx](https://www.python-httpx.org/) (`pip install httpx`)

## Usage

```sh
python3 accrescent.py [options]
```

### Options

- `--endpoint URL`  
  Repository endpoint to poll (default: `https://repo.accrescent.app/repodata.0.json`)

- `--interval SECONDS`  
  Polling interval in seconds (default: `300`)

- `--state-file PATH`  
  Path to the local state file (default: `known_apps.json`)

- `--log-file PATH`  
  Path to the log file (default: `app_updates.log`)

- `--log-level LEVEL`  
  Logging level: `DEBUG`, `INFO`, `WARNING`, or `ERROR` (default: `INFO`)

- `--quiet`  
  Suppress console output (only log to file)

- `--once`  
  Run a single check and exit

- `--max-failures N`  
  Maximum consecutive failures before exit (default: `5`)

## Example

```sh
python3 accrescent.py --interval 600 --log-level DEBUG
```

## How It Works

1. On startup, loads the known apps state from the specified file.
2. Polls the repository endpoint for the latest app metadata.
3. Compares the new data with the previous state to detect changes.
4. Logs and prints notifications for any detected changes.
5. Updates the local state file.
6. Repeats at the specified interval, or exits if `--once` is used.

## Graceful Shutdown

The script handles `SIGINT` and `SIGTERM` signals, ensuring the current state is saved before exiting.

## License

See [LICENSE](LICENSE) for details.

---

*This script is not affiliated with Accrescent.
