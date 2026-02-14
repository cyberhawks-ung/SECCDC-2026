# AltAcctee

Alternative access tool for blue team competitions. Provides a backup way to reach your machines if the red team kills other access methods (SSH, RDP, etc.).

**Security disclaimer**: This tool uses hardcoded credentials and is intended only for controlled blue team competition environments. Do not use in production. Consider rotating the password or loading from an environment variable for different events.

## Requirements

- Python 3.9+
- No external dependencies for core functionality

## Deployment

### Server (run on each target machine)

The server must run with elevated privileges (root on Linux, Administrator on Windows) for full access.

**Linux:**
```bash
sudo python3 server.py
# Or with custom port:
sudo python3 server.py -p 44158
```

**Windows (run as Administrator):**
```cmd
python server.py
```

**Environment variable:** Set `ALTACCTEE_PORT` to override the default port (44158).

**Firewall:** Ensure the chosen port (default 44158) is allowed inbound on each target.

### Client (run on management machine)

1. Copy `hosts.example.json` to `hosts.json` (in current directory or `~/.altacctee/hosts.json`)
2. Edit `hosts.json` with your server IPs:

```json
{
  "hosts": [
    {"ip": "192.168.1.10", "port": 44158, "os": "linux"},
    {"ip": "192.168.1.11", "port": 44158, "os": "windows"}
  ]
}
```

## Logging

All commands are logged on the management machine: both `run` (one-shot) and `shell` (interactive). Logs are stored per machine in `~/.altacctee/logs/` (override with `--log-dir`). Each file is named by IP (e.g. `192_168_1_10.log`). Each entry includes:

- Timestamp (UTC)
- Input command
- Exit code (run only) or output (both)
- Output (first 500 characters if longer)

Shell sessions log each command you type (on Enter) and the resulting output. Works best for interactive use; piped/scripted input may log commands before output arrives.

## Usage

### Execute a command on hosts

Single host:
```bash
python client.py run whoami --host 192.168.1.10
```

All hosts of a given OS:
```bash
python client.py run "hostname" --os linux
python client.py run "hostname" --os windows
```

Specific hosts by IP list:
```bash
python client.py run "id" --hosts 192.168.1.10,192.168.1.11
```

### Interactive shell

Connect to a single host for an interactive root/admin shell:

```bash
python client.py shell --host 192.168.1.10
```

Exit with `exit` or Ctrl+D.

## Credentials

Default password: `CyberHawksRulez` (hardcoded in `protocol.py`)

## Persistence (optional)

- **Linux**: Use a systemd unit or add to cron
- **Windows**: Use NSSM or Task Scheduler to run the server as a service
