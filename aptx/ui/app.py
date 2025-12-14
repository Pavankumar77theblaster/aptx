"""
APT-X FastAPI Application
=========================

Main FastAPI application with API routes and web interface.
"""

import asyncio
from typing import List, Optional
from datetime import datetime

from fastapi import FastAPI, HTTPException, BackgroundTasks, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from aptx import __version__
from aptx.core.database import get_database
from aptx.core.config import get_config
from aptx.core.pipeline import create_default_pipeline


# Pydantic models for API
class ScanRequest(BaseModel):
    target: str
    name: Optional[str] = None
    vuln_types: Optional[List[str]] = []
    stages: Optional[List[str]] = []
    safe_mode: bool = True


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str


def create_app() -> FastAPI:
    """Create and configure FastAPI application."""
    app = FastAPI(
        title="APT-X",
        description="Automated Penetration Testing Framework",
        version=__version__,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
    )

    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Database
    db = get_database()

    # Background scan tasks
    running_scans = {}

    @app.get("/", response_class=HTMLResponse)
    async def dashboard():
        """Main dashboard."""
        scans = db.list_scans(limit=10)
        stats = {
            "total_scans": len(db.list_scans(limit=1000)),
            "running": len([s for s in scans if s["status"] == "running"]),
            "completed": len([s for s in scans if s["status"] == "completed"]),
        }

        return f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>APT-X Dashboard</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #f5f7fa; }}
        .header {{ background: #2563eb; color: white; padding: 20px 40px; }}
        .header h1 {{ font-size: 24px; font-weight: 600; }}
        .container {{ max-width: 1400px; margin: 0 auto; padding: 30px; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .stat-card {{ background: white; border-radius: 8px; padding: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        .stat-card h3 {{ color: #6b7280; font-size: 14px; font-weight: 500; margin-bottom: 8px; }}
        .stat-card .value {{ font-size: 32px; font-weight: 700; color: #1f2937; }}
        .card {{ background: white; border-radius: 8px; padding: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 20px; }}
        .card h2 {{ font-size: 18px; color: #1f2937; margin-bottom: 20px; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #e5e7eb; }}
        th {{ color: #6b7280; font-weight: 500; font-size: 14px; }}
        .status {{ padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: 500; }}
        .status.running {{ background: #dbeafe; color: #1d4ed8; }}
        .status.completed {{ background: #d1fae5; color: #059669; }}
        .status.failed {{ background: #fee2e2; color: #dc2626; }}
        .btn {{ background: #2563eb; color: white; padding: 10px 20px; border: none; border-radius: 6px; cursor: pointer; font-size: 14px; }}
        .btn:hover {{ background: #1d4ed8; }}
        .form-group {{ margin-bottom: 16px; }}
        .form-group label {{ display: block; margin-bottom: 6px; color: #374151; font-weight: 500; }}
        .form-group input {{ width: 100%; padding: 10px; border: 1px solid #d1d5db; border-radius: 6px; font-size: 14px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>APT-X Dashboard</h1>
    </div>

    <div class="container">
        <div class="stats">
            <div class="stat-card">
                <h3>Total Scans</h3>
                <div class="value">{stats['total_scans']}</div>
            </div>
            <div class="stat-card">
                <h3>Running</h3>
                <div class="value" style="color: #2563eb;">{stats['running']}</div>
            </div>
            <div class="stat-card">
                <h3>Completed</h3>
                <div class="value" style="color: #059669;">{stats['completed']}</div>
            </div>
        </div>

        <div class="card">
            <h2>New Scan</h2>
            <form id="scanForm">
                <div class="form-group">
                    <label>Target</label>
                    <input type="text" id="target" placeholder="example.com" required>
                </div>
                <div class="form-group">
                    <label>
                        <input type="checkbox" id="safeMode" checked> Safe Mode
                    </label>
                </div>
                <button type="submit" class="btn">Start Scan</button>
            </form>
        </div>

        <div class="card">
            <h2>Recent Scans</h2>
            <table>
                <thead>
                    <tr>
                        <th>Target</th>
                        <th>Status</th>
                        <th>Findings</th>
                        <th>Created</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join(f'''
                    <tr>
                        <td>{s['target']}</td>
                        <td><span class="status {s['status']}">{s['status']}</span></td>
                        <td>{s.get('total_findings', 0)}</td>
                        <td>{s['created_at'][:19] if s.get('created_at') else '-'}</td>
                    </tr>
                    ''' for s in scans)}
                </tbody>
            </table>
        </div>
    </div>

    <script>
        document.getElementById('scanForm').addEventListener('submit', async (e) => {{
            e.preventDefault();
            const target = document.getElementById('target').value;
            const safeMode = document.getElementById('safeMode').checked;

            const response = await fetch('/api/scans', {{
                method: 'POST',
                headers: {{'Content-Type': 'application/json'}},
                body: JSON.stringify({{target, safe_mode: safeMode}})
            }});

            const data = await response.json();
            alert('Scan started: ' + data.scan_id);
            location.reload();
        }});
    </script>
</body>
</html>
"""

    @app.get("/api/health")
    async def health():
        """Health check endpoint."""
        return {"status": "healthy", "version": __version__}

    @app.post("/api/scans", response_model=ScanResponse)
    async def create_scan(request: ScanRequest, background_tasks: BackgroundTasks):
        """Create a new scan."""
        scan = db.create_scan(
            target=request.target,
            name=request.name,
            vuln_types=request.vuln_types,
            stages=request.stages,
            safe_mode=request.safe_mode
        )

        # Start scan in background
        async def run_scan(scan_id: str, target: str, safe_mode: bool):
            pipeline = create_default_pipeline()
            try:
                await pipeline.run(
                    target=target,
                    safe_mode=safe_mode
                )
            except Exception as e:
                db.update_scan(scan_id, status="failed")

        background_tasks.add_task(
            run_scan,
            scan["id"],
            request.target,
            request.safe_mode
        )

        return ScanResponse(
            scan_id=scan["id"],
            status="started",
            message=f"Scan started for {request.target}"
        )

    @app.get("/api/scans")
    async def list_scans(
        status: Optional[str] = None,
        limit: int = 50
    ):
        """List all scans."""
        scans = db.list_scans(status=status, limit=limit)
        return {"scans": scans, "total": len(scans)}

    @app.get("/api/scans/{scan_id}")
    async def get_scan(scan_id: str):
        """Get scan details."""
        scan = db.get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        return scan

    @app.get("/api/scans/{scan_id}/findings")
    async def get_findings(scan_id: str, severity: Optional[str] = None):
        """Get findings for a scan."""
        findings = db.get_findings(scan_id, severity=severity)
        return {"findings": findings, "total": len(findings)}

    @app.get("/api/scans/{scan_id}/report")
    async def generate_report(scan_id: str, format: str = "json"):
        """Generate scan report."""
        scan = db.get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        findings = db.get_findings(scan_id)

        from aptx.reporting.generator import ReportGenerator
        generator = ReportGenerator()
        report_data = generator._prepare_report_data(scan, findings, {})

        if format == "json":
            return report_data
        else:
            raise HTTPException(status_code=400, detail="Use CLI for HTML/PDF reports")

    return app
