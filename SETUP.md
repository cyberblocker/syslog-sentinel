# Setup: first run to two-machine lab

## 1. Prepare your computer

Use Windows, macOS, or Linux with Python 3.10 or newer. No pip installs are required.
Download Python from https://www.python.org/downloads/ if needed. On Windows enable the installer option to add Python to PATH, then reopen your terminal.

Extract the ZIP first. Open the inner `syslog-sentinel` folder that contains `sentinel.py`.

- Windows: open that folder in File Explorer, click the address bar, type `powershell`, and press Enter.
- macOS: open Terminal, type `cd `, drag the extracted folder onto the terminal, then press Enter.
- Linux: right-click the folder and choose Open in Terminal, or use `cd /path/to/syslog-sentinel`.

Run `python --version`. Replace `python` with `python3` or `py` throughout this guide if that is your installed command.

## 2. Start collecting

```bash
python sentinel.py collect
```

Keep this terminal open. It should show `Listening on 127.0.0.1:5514 TCP + UDP`.
The collector writes to `data/events.db`. Port 5514 avoids privileged port 514.

## 3. Send and inspect

Open another terminal in the same folder:

```bash
python sentinel.py demo
python sentinel.py report
```

Open `reports/report.html` in your browser. Search for `198.51.100.23`. Review SSH-001, SSH-002, and db-01's never-seen status. The demo only transmits log text. It makes no SSH login attempts and attacks no host.

Try UDP:

```bash
python sentinel.py demo --transport udp
python sentinel.py report
```

## 4. Demonstrate a collection gap

After the demo, wait more than two minutes, then rerun the report command. web-01 and fw-01 should become silent. Alternatively, use `python sentinel.py report --silence 10` after ten seconds. Rerun the demo and report to restore recent status.

## 5. Reset or stop

Press Ctrl+C in the collector terminal to stop it. For a clean demonstration, stop it and rename the `data` folder to `data-backup` in your file manager. Restart the collector to create a fresh database. Keep the backup if it contains evidence you need. Generated reports are overwritten by subsequent report commands.

## 6. Add a real Linux client

Use two VMs on a private lab network. Start the collector on the server VM with its actual private IP:

```bash
python sentinel.py collect --bind 192.168.56.10
```

Replace that address with your own. Allow TCP port 5514 only from the client IP in your VM/host firewall. Keep the listener off public networks. This lab transport is unencrypted and unauthenticated.

On a Linux client that already runs rsyslog:

1. Copy `examples/60-sentinel.conf` to `/etc/rsyslog.d/60-sentinel.conf` with administrator privileges.
2. Replace `192.0.2.10` in that file with the collector's private IP.
3. Validate and restart:

   ```bash
   sudo rsyslogd -N1
   sudo systemctl restart rsyslog
   logger -t sentinel-test "hello from my Linux lab client"
   ```

4. On the collector, regenerate the report. Confirm the message and hostname arrived.
5. Add the received hostname to `inventory.json`, preserving valid JSON.

The supplied rsyslog filter forwards only `sentinel-test` messages. It uses a memory queue, which does not survive a client crash. Broader forwarding, disk queues, and TLS are follow-up exercises. Some distributions use different service managers; the commands above target systemd Linux.

## Optional Docker path

Install Docker with Compose, then run from the project folder:

```bash
docker compose up -d --build
docker compose exec collector python sentinel.py demo
docker compose exec collector python sentinel.py report
docker compose cp collector:/app/reports ./reports
```

Open the copied `reports/report.html`. The demo runs inside the container; host-published ports also allow a sender running on your computer to reach the collector. Published ports are restricted to localhost. SQLite persists in the named `sentinel-data` volume. Stop with `docker compose down`; this retains data. Do not use `down -v` unless you intend to delete the collected data.

Docker was not available in the build environment; this optional path needs a local smoke test. GitHub Actions includes a Docker build check.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `python` not found | Try `python3` or `py`; install Python if neither exists |
| Cannot open sentinel.py | Change to the extracted folder containing that file |
| Address already in use | Stop the existing collector or use `--port 5515` for both collector and demo |
| TCP connection refused | Start the collector first; verify IP, port, and firewall |
| UDP says sent but no logs | UDP has no delivery acknowledgment; verify listener and network settings |
| Report unchanged | Rerun the report command and refresh/reopen the HTML |
| No database | Use the same working directory as the collector or specify `--db` |
| Unexpected counts | Old events persist; use the reset procedure for a fresh demo |
| Real device is missing from rules | Check raw text and parsed status; only the documented formats and sshd messages match |

To inspect raw stored JSON, open `data/events.db` in a SQLite viewer and inspect the `events` table. Avoid editing the active database.
