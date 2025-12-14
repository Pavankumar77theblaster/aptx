# APT-X Architecture

## Overview

APT-X follows a modular, pipeline-based architecture designed for extensibility and maintainability.

## Core Components

### 1. Configuration (core/config.py)
- YAML-based configuration
- Environment variable overrides
- Hierarchical settings

### 2. Database (core/database.py)
- SQLAlchemy ORM
- SQLite (default) / PostgreSQL support
- Models: Scan, Finding, Scope, Intelligence

### 3. Pipeline (core/pipeline.py)
- Stage-based execution
- Dependency resolution
- Progress tracking
- Async execution

### 4. Scope Validator (core/scope.py)
- IP/domain allowlists
- CIDR range support
- Wildcard matching
- Private IP blocking

### 5. Rate Limiter (core/rate_limiter.py)
- Token bucket algorithm
- Per-target limits
- Automatic cooldown

## Pipeline Stages

```
1. Target Intake     → Parse and validate input
2. Scope Validation  → Verify authorization
3. Subdomain Enum    → Discover subdomains
4. Port Scan         → Identify open ports
5. Web Discovery     → Find web servers
6. Crawling          → Map attack surface
7. Parameter Disc    → Find input points
8. Vuln Scan         → Detect vulnerabilities
9. Validation        → Confirm findings
10. Reporting        → Generate output
```

## Data Flow

```
User Input → CLI → Pipeline → Stages → Database → Report
                      ↓
                Intelligence Engine
                      ↓
              Data Classification
```

## Module Dependencies

```
core/
  ├── config ← database, logger
  ├── database
  ├── logger
  ├── scope ← logger
  ├── pipeline ← config, database, logger, scope
  └── rate_limiter ← logger

tools/ ← core
recon/ ← core, tools
discovery/ ← core, tools
vulnerabilities/ ← core
intelligence/ ← core
reporting/ ← core
ui/ ← core
plugins/ ← all
```

## Security Design

1. **Defense in Depth**: Multiple validation layers
2. **Principle of Least Privilege**: Minimal permissions
3. **Audit Trail**: Complete logging
4. **Safe Defaults**: Non-destructive mode enabled
5. **Input Validation**: All user input sanitized
