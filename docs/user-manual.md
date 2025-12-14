# APT-X User Manual

## Getting Started

### Installation

```bash
pip install -e .
aptx init
```

### First Scan

1. Create a scope file:
```yaml
# scope.yaml
name: "My Test"
allowed_domains:
  - "example.com"
  - "*.example.com"
strict_mode: true
```

2. Run scan:
```bash
aptx scan example.com --scope-file scope.yaml --safe-mode
```

## CLI Reference

### scan
```bash
aptx scan TARGET [OPTIONS]

Options:
  --name TEXT          Scan name
  --vulns TEXT         Vulnerability types (comma-separated)
  --stages TEXT        Pipeline stages to run
  --safe-mode          Enable non-destructive mode (default)
  --no-safe-mode       Disable safe mode
  --scope-file PATH    Scope configuration file
  --rate-limit FLOAT   Requests per second
```

### report
```bash
aptx report SCAN_ID [OPTIONS]

Options:
  --format [html|pdf|json]  Output format
  --output PATH             Output file
```

### scans
```bash
aptx scans [OPTIONS]

Options:
  --status [pending|running|completed|failed]
  --limit INTEGER
```

## Configuration

### Config Locations
1. `config/default.yaml` - Default settings
2. `~/.aptx/local.yaml` - User overrides
3. Environment variables (APTX_*)

### Key Settings

```yaml
safety:
  safe_mode: true
  rate_limit: 10
  require_authorization: true

scope:
  strict_mode: true
  block_private_ips: true

vulnerabilities:
  scanners:
    sqli:
      enabled: true
      time_based: false  # Disabled in safe mode
```

## Vulnerability Scanners

### SQL Injection
- Error-based detection
- Boolean-based detection
- Safe mode: No time-based tests

### XSS
- Reflected XSS
- DOM-based indicators
- Context-aware analysis

### Others
- IDOR, Auth Bypass, SSRF
- Command Injection, Open Redirect
- Security Misconfigurations

## Web Interface

Start: `aptx ui --port 8080`

Features:
- Dashboard with statistics
- New scan creation
- Findings browser
- Report generation

## Best Practices

1. **Always use scope files** for production scans
2. **Start with safe mode** enabled
3. **Review findings** before validation
4. **Document authorization** before testing
5. **Use rate limiting** to avoid disruption
