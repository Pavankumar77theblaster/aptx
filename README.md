# APT-X: Automated Penetration Testing - eXtended

**Enterprise-grade Automated Penetration Testing Framework**

APT-X is a modular, intelligent, and extensible penetration testing framework designed for professional Red Team operations. Built for Kali Linux, it automates reconnaissance, vulnerability discovery, validation, and reporting while maintaining strict safety controls.

## Features

- **Automated Pipeline**: Complete penetration testing workflow from reconnaissance to reporting
- **Intelligent Detection**: 9 built-in vulnerability scanners (SQLi, XSS, IDOR, SSRF, etc.)
- **Safe Mode**: Non-destructive testing by default with scope enforcement
- **Tool Integration**: Wraps Nmap, Amass, Subfinder, httpx, Nuclei, ffuf, Nikto, SQLMap
- **Intelligence Engine**: Auto-classification of security data without ML dependencies
- **Professional Reporting**: HTML, PDF, and JSON reports with CVSS scoring
- **Web UI**: Clean, enterprise-ready FastAPI dashboard
- **Extensible**: Plugin SDK for custom scanners and modules

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/aptx-framework/aptx.git
cd aptx

# Install dependencies
pip install -e .

# Initialize APT-X
aptx init
```

### Basic Usage

```bash
# Run a safe scan
aptx scan example.com --safe-mode

# Scan with specific vulnerability types
aptx scan example.com --vulns sqli,xss

# Generate report
aptx report <scan_id> --format html

# Start web UI
aptx ui --port 8080
```

## Architecture

```
aptx/
├── core/           # Core framework (config, database, logging, pipeline)
├── recon/          # Reconnaissance modules
├── discovery/      # Content discovery
├── vulnerabilities/# Vulnerability scanners
├── validation/     # PoC validation
├── intelligence/   # Data classification & learning
├── data_feeds/     # External data ingestion
├── reporting/      # Report generation
├── tools/          # External tool wrappers
├── ui/             # Web interface
└── plugins/        # Plugin system
```

## Supported Vulnerability Types

| Type | Description |
|------|-------------|
| SQLi | SQL Injection (error, boolean, time-based) |
| XSS | Cross-Site Scripting (reflected, stored, DOM) |
| IDOR | Insecure Direct Object Reference |
| Auth Bypass | Authentication/Authorization bypass |
| File Upload | Unrestricted file upload |
| Command Injection | OS command injection |
| SSRF | Server-Side Request Forgery |
| Open Redirect | Unvalidated redirects |
| Misconfig | Security misconfigurations |

## Safety Features

- **Authorization Warning**: Requires explicit consent before scanning
- **Scope Enforcement**: Strict allowlist-based target validation
- **Safe Mode**: Non-destructive payloads only (default)
- **Rate Limiting**: Configurable request throttling
- **Audit Logging**: Complete activity trail for compliance

## CLI Commands

```bash
aptx --help                    # Show help
aptx init                      # Initialize framework
aptx scan <target>            # Run penetration test
aptx scans                    # List all scans
aptx report <scan_id>         # Generate report
aptx feed ingest <source>     # Ingest intelligence data
aptx config show              # Show configuration
aptx ui                       # Start web interface
aptx check-scope <target>     # Validate target scope
```

## Configuration

Configuration is stored in YAML format:

```yaml
# ~/.aptx/local.yaml
safety:
  require_authorization: true
  safe_mode: true
  rate_limit: 10

scope:
  strict_mode: true
  block_private_ips: true

vulnerabilities:
  scanners:
    sqli:
      enabled: true
    xss:
      enabled: true
```

## Plugin Development

Create custom scanners by extending the plugin SDK:

```python
from aptx.plugins.sdk import VulnerabilityPlugin, PluginMetadata

class MyScanner(VulnerabilityPlugin):
    metadata = PluginMetadata(
        name="my_scanner",
        version="1.0.0",
        author="Your Name",
        description="Custom vulnerability scanner",
        category="vulnerability"
    )

    async def scan(self, target, options=None):
        # Your scanning logic
        return []
```

## Web UI

The web interface provides:
- Dashboard with scan statistics
- Scan management and monitoring
- Findings browser with severity filtering
- Report generation
- Intelligence feed management

Access at `http://localhost:8080` after running `aptx ui`.

## Requirements

- Python 3.9+
- Kali Linux (recommended) or Linux with security tools installed
- Nmap, Amass, Subfinder, httpx (optional but recommended)

## Legal Notice

**APT-X is designed for authorized security testing only.**

- Only use against systems you have explicit permission to test
- Unauthorized access to computer systems is illegal
- Users accept full responsibility for their actions
- Always obtain written authorization before testing

## License

MIT License - See LICENSE file for details.

## Contributing

Contributions welcome! Please read CONTRIBUTING.md for guidelines.

## Support

- Documentation: [docs/](docs/)
- Issues: GitHub Issues
- Security: Report vulnerabilities responsibly

---

**APT-X** - Professional penetration testing automation for the modern Red Team.
