"""
APT-X Database Module
=====================

Database abstraction layer supporting SQLite and PostgreSQL.
Uses SQLAlchemy ORM for database operations with async support.
"""

import uuid
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Type, TypeVar, Union
from contextlib import contextmanager

from sqlalchemy import (
    create_engine,
    Column,
    String,
    Integer,
    Float,
    Boolean,
    DateTime,
    Text,
    JSON,
    ForeignKey,
    Index,
    event,
    Enum as SQLEnum
)
from sqlalchemy.orm import (
    sessionmaker,
    declarative_base,
    Session,
    relationship,
    scoped_session
)
from sqlalchemy.pool import StaticPool
from enum import Enum

from aptx.core.exceptions import DatabaseError


# SQLAlchemy base
Base = declarative_base()
T = TypeVar("T", bound=Base)


class ScanStatus(str, Enum):
    """Scan status enumeration."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Severity(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityType(str, Enum):
    """Supported vulnerability types."""
    SQLI = "sqli"
    XSS = "xss"
    IDOR = "idor"
    AUTH_BYPASS = "auth_bypass"
    FILE_UPLOAD = "file_upload"
    COMMAND_INJECTION = "command_injection"
    SSRF = "ssrf"
    OPEN_REDIRECT = "open_redirect"
    MISCONFIG = "misconfig"
    OTHER = "other"


# Database Models

class Scan(Base):
    """Scan model representing a penetration test scan."""

    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(255), nullable=True)
    target = Column(String(500), nullable=False, index=True)
    status = Column(String(20), default=ScanStatus.PENDING.value, index=True)
    scope_id = Column(String(36), ForeignKey("scopes.id"), nullable=True)

    # Configuration
    config = Column(JSON, default=dict)
    stages = Column(JSON, default=list)  # List of stages to run
    vuln_types = Column(JSON, default=list)  # Vulnerability types to check
    safe_mode = Column(Boolean, default=True)

    # Timing
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    # Results summary
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)

    # Ownership
    owner = Column(String(100), nullable=True)
    notes = Column(Text, nullable=True)

    # Relationships
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    scope = relationship("Scope", back_populates="scans")

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "target": self.target,
            "status": self.status,
            "scope_id": self.scope_id,
            "config": self.config,
            "stages": self.stages,
            "vuln_types": self.vuln_types,
            "safe_mode": self.safe_mode,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "total_findings": self.total_findings,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "info_count": self.info_count,
            "owner": self.owner,
        }


class Finding(Base):
    """Finding model representing a detected vulnerability."""

    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False, index=True)

    # Vulnerability details
    vuln_type = Column(String(50), nullable=False, index=True)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(20), nullable=False, index=True)
    confidence = Column(Integer, default=50)  # 0-100

    # Location
    url = Column(String(2000), nullable=True)
    parameter = Column(String(255), nullable=True)
    method = Column(String(10), nullable=True)
    endpoint = Column(String(1000), nullable=True)

    # Evidence
    request = Column(Text, nullable=True)
    response = Column(Text, nullable=True)
    evidence = Column(Text, nullable=True)
    poc = Column(Text, nullable=True)  # Proof of concept

    # Scoring
    cvss_score = Column(Float, nullable=True)
    cvss_vector = Column(String(100), nullable=True)

    # Remediation
    remediation = Column(Text, nullable=True)
    references = Column(JSON, default=list)

    # Validation
    validated = Column(Boolean, default=False)
    false_positive = Column(Boolean, default=False)
    validation_notes = Column(Text, nullable=True)

    # Metadata
    detected_at = Column(DateTime, default=datetime.utcnow)
    validated_at = Column(DateTime, nullable=True)
    tool = Column(String(50), nullable=True)
    raw_output = Column(JSON, nullable=True)

    # Relationships
    scan = relationship("Scan", back_populates="findings")

    __table_args__ = (
        Index("ix_findings_scan_severity", "scan_id", "severity"),
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "vuln_type": self.vuln_type,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "confidence": self.confidence,
            "url": self.url,
            "parameter": self.parameter,
            "method": self.method,
            "endpoint": self.endpoint,
            "evidence": self.evidence,
            "poc": self.poc,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "remediation": self.remediation,
            "references": self.references,
            "validated": self.validated,
            "false_positive": self.false_positive,
            "detected_at": self.detected_at.isoformat() if self.detected_at else None,
            "tool": self.tool,
        }


class Scope(Base):
    """Scope model defining allowed targets."""

    __tablename__ = "scopes"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)

    # Allowlist
    allowed_domains = Column(JSON, default=list)
    allowed_ips = Column(JSON, default=list)
    allowed_cidrs = Column(JSON, default=list)

    # Blocklist
    blocked_domains = Column(JSON, default=list)
    blocked_ips = Column(JSON, default=list)
    blocked_paths = Column(JSON, default=list)

    # Settings
    strict_mode = Column(Boolean, default=True)
    block_private = Column(Boolean, default=True)

    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    scans = relationship("Scan", back_populates="scope")

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "allowed_domains": self.allowed_domains,
            "allowed_ips": self.allowed_ips,
            "allowed_cidrs": self.allowed_cidrs,
            "blocked_domains": self.blocked_domains,
            "blocked_ips": self.blocked_ips,
            "blocked_paths": self.blocked_paths,
            "strict_mode": self.strict_mode,
            "block_private": self.block_private,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Intelligence(Base):
    """Intelligence data model for storing processed security data."""

    __tablename__ = "intelligence"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    # Classification
    data_type = Column(String(50), nullable=False, index=True)  # payload, wordlist, bypass, etc.
    category = Column(String(50), nullable=True, index=True)  # sqli, xss, etc.
    subcategory = Column(String(50), nullable=True)

    # Content
    content = Column(Text, nullable=False)
    normalized_content = Column(Text, nullable=True)
    hash = Column(String(64), nullable=True, unique=True)  # For deduplication

    # Source
    source = Column(String(255), nullable=True)
    source_url = Column(String(2000), nullable=True)
    source_type = Column(String(50), nullable=True)  # file, github, url, manual

    # Metadata
    confidence = Column(Integer, default=50)
    usage_stage = Column(String(50), nullable=True)  # recon, detection, validation
    tags = Column(JSON, default=list)
    extra_data = Column(JSON, default=dict)

    # Effectiveness tracking
    times_used = Column(Integer, default=0)
    successful_detections = Column(Integer, default=0)
    false_positives = Column(Integer, default=0)
    effectiveness_score = Column(Float, default=0.0)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_used_at = Column(DateTime, nullable=True)

    __table_args__ = (
        Index("ix_intelligence_type_category", "data_type", "category"),
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "data_type": self.data_type,
            "category": self.category,
            "content": self.content[:500] if self.content else None,  # Truncate
            "source": self.source,
            "confidence": self.confidence,
            "usage_stage": self.usage_stage,
            "tags": self.tags,
            "effectiveness_score": self.effectiveness_score,
            "times_used": self.times_used,
        }


class Feedback(Base):
    """User feedback model for continuous learning."""

    __tablename__ = "feedback"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    finding_id = Column(String(36), ForeignKey("findings.id"), nullable=True)
    intelligence_id = Column(String(36), ForeignKey("intelligence.id"), nullable=True)

    # Feedback type
    feedback_type = Column(String(50), nullable=False)  # confirmed, false_positive, etc.
    comment = Column(Text, nullable=True)

    # Context
    scan_id = Column(String(36), nullable=True)
    target = Column(String(500), nullable=True)
    vuln_type = Column(String(50), nullable=True)

    # User
    user = Column(String(100), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "finding_id": self.finding_id,
            "feedback_type": self.feedback_type,
            "comment": self.comment,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Database:
    """
    Database manager for APT-X framework.

    Provides connection management, session handling, and CRUD operations
    for all database models.
    """

    def __init__(
        self,
        engine: str = "sqlite",
        sqlite_path: Optional[str] = None,
        postgres_url: Optional[str] = None,
        echo: bool = False
    ):
        """
        Initialize database connection.

        Args:
            engine: Database engine ("sqlite" or "postgresql")
            sqlite_path: Path for SQLite database
            postgres_url: PostgreSQL connection URL
            echo: Echo SQL statements (for debugging)
        """
        self.engine_type = engine

        if engine == "sqlite":
            db_path = Path(sqlite_path or "~/.aptx/aptx.db").expanduser()
            db_path.parent.mkdir(parents=True, exist_ok=True)
            url = f"sqlite:///{db_path}"
            self.engine = create_engine(
                url,
                echo=echo,
                connect_args={"check_same_thread": False},
                poolclass=StaticPool
            )
        elif engine == "postgresql":
            if not postgres_url:
                raise DatabaseError("PostgreSQL URL required")
            self.engine = create_engine(postgres_url, echo=echo)
        else:
            raise DatabaseError(f"Unsupported database engine: {engine}")

        # Enable foreign keys for SQLite
        if engine == "sqlite":
            @event.listens_for(self.engine, "connect")
            def set_sqlite_pragma(dbapi_conn, connection_record):
                cursor = dbapi_conn.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.close()

        # Create session factory
        self.SessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=self.engine
        )
        self.ScopedSession = scoped_session(self.SessionLocal)

    def create_tables(self) -> None:
        """Create all database tables."""
        Base.metadata.create_all(bind=self.engine)

    def drop_tables(self) -> None:
        """Drop all database tables."""
        Base.metadata.drop_all(bind=self.engine)

    @contextmanager
    def session(self):
        """
        Provide a transactional scope around a series of operations.

        Usage:
            with db.session() as session:
                session.add(new_scan)
        """
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            raise DatabaseError(f"Database operation failed: {e}")
        finally:
            session.close()

    def get_session(self) -> Session:
        """Get a new session."""
        return self.SessionLocal()

    # Scan operations

    def create_scan(
        self,
        target: str,
        name: Optional[str] = None,
        config: Optional[Dict] = None,
        stages: Optional[List[str]] = None,
        vuln_types: Optional[List[str]] = None,
        safe_mode: bool = True,
        scope_id: Optional[str] = None,
        owner: Optional[str] = None
    ) -> Scan:
        """Create a new scan."""
        with self.session() as session:
            scan = Scan(
                target=target,
                name=name or f"Scan of {target}",
                config=config or {},
                stages=stages or [],
                vuln_types=vuln_types or [],
                safe_mode=safe_mode,
                scope_id=scope_id,
                owner=owner
            )
            session.add(scan)
            session.flush()
            scan_dict = scan.to_dict()
            return scan

    def get_scan(self, scan_id: str) -> Optional[Dict]:
        """Get scan by ID."""
        with self.session() as session:
            scan = session.query(Scan).filter(Scan.id == scan_id).first()
            return scan.to_dict() if scan else None

    def update_scan(self, scan_id: str, **kwargs) -> Optional[Dict]:
        """Update scan attributes."""
        with self.session() as session:
            scan = session.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                for key, value in kwargs.items():
                    if hasattr(scan, key):
                        setattr(scan, key, value)
                session.flush()
                return scan.to_dict()
            return None

    def list_scans(
        self,
        status: Optional[str] = None,
        target: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict]:
        """List scans with optional filters."""
        with self.session() as session:
            query = session.query(Scan)
            if status:
                query = query.filter(Scan.status == status)
            if target:
                query = query.filter(Scan.target.ilike(f"%{target}%"))
            query = query.order_by(Scan.created_at.desc())
            query = query.offset(offset).limit(limit)
            return [s.to_dict() for s in query.all()]

    # Finding operations

    def add_finding(
        self,
        scan_id: str,
        vuln_type: str,
        title: str,
        severity: str,
        **kwargs
    ) -> Dict:
        """Add a finding to a scan."""
        with self.session() as session:
            finding = Finding(
                scan_id=scan_id,
                vuln_type=vuln_type,
                title=title,
                severity=severity,
                **kwargs
            )
            session.add(finding)

            # Update scan counts
            scan = session.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.total_findings = (scan.total_findings or 0) + 1
                severity_attr = f"{severity.lower()}_count"
                if hasattr(scan, severity_attr):
                    setattr(scan, severity_attr, (getattr(scan, severity_attr) or 0) + 1)

            session.flush()
            return finding.to_dict()

    def get_findings(
        self,
        scan_id: str,
        severity: Optional[str] = None,
        vuln_type: Optional[str] = None,
        validated: Optional[bool] = None
    ) -> List[Dict]:
        """Get findings for a scan."""
        with self.session() as session:
            query = session.query(Finding).filter(Finding.scan_id == scan_id)
            if severity:
                query = query.filter(Finding.severity == severity)
            if vuln_type:
                query = query.filter(Finding.vuln_type == vuln_type)
            if validated is not None:
                query = query.filter(Finding.validated == validated)
            return [f.to_dict() for f in query.all()]

    # Scope operations

    def create_scope(
        self,
        name: str,
        allowed_domains: Optional[List[str]] = None,
        allowed_ips: Optional[List[str]] = None,
        **kwargs
    ) -> Dict:
        """Create a new scope."""
        with self.session() as session:
            scope = Scope(
                name=name,
                allowed_domains=allowed_domains or [],
                allowed_ips=allowed_ips or [],
                **kwargs
            )
            session.add(scope)
            session.flush()
            return scope.to_dict()

    def get_scope(self, scope_id: str) -> Optional[Dict]:
        """Get scope by ID."""
        with self.session() as session:
            scope = session.query(Scope).filter(Scope.id == scope_id).first()
            return scope.to_dict() if scope else None

    # Intelligence operations

    def add_intelligence(
        self,
        data_type: str,
        content: str,
        category: Optional[str] = None,
        source: Optional[str] = None,
        **kwargs
    ) -> Dict:
        """Add intelligence data."""
        import hashlib
        content_hash = hashlib.sha256(content.encode()).hexdigest()

        with self.session() as session:
            # Check for duplicate
            existing = session.query(Intelligence).filter(
                Intelligence.hash == content_hash
            ).first()
            if existing:
                return existing.to_dict()

            intel = Intelligence(
                data_type=data_type,
                content=content,
                category=category,
                source=source,
                hash=content_hash,
                **kwargs
            )
            session.add(intel)
            session.flush()
            return intel.to_dict()

    def get_intelligence(
        self,
        data_type: Optional[str] = None,
        category: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict]:
        """Get intelligence data."""
        with self.session() as session:
            query = session.query(Intelligence)
            if data_type:
                query = query.filter(Intelligence.data_type == data_type)
            if category:
                query = query.filter(Intelligence.category == category)
            query = query.order_by(Intelligence.effectiveness_score.desc())
            query = query.limit(limit)
            return [i.to_dict() for i in query.all()]

    def update_intelligence_effectiveness(
        self,
        intel_id: str,
        success: bool
    ) -> None:
        """Update intelligence effectiveness based on usage."""
        with self.session() as session:
            intel = session.query(Intelligence).filter(
                Intelligence.id == intel_id
            ).first()
            if intel:
                intel.times_used = (intel.times_used or 0) + 1
                intel.last_used_at = datetime.utcnow()
                if success:
                    intel.successful_detections = (intel.successful_detections or 0) + 1
                else:
                    intel.false_positives = (intel.false_positives or 0) + 1
                # Calculate effectiveness
                if intel.times_used > 0:
                    intel.effectiveness_score = (
                        intel.successful_detections / intel.times_used * 100
                    )


# Global database instance
_database: Optional[Database] = None


def get_database(
    engine: str = "sqlite",
    sqlite_path: Optional[str] = None,
    reinit: bool = False
) -> Database:
    """
    Get or create the global database instance.

    Args:
        engine: Database engine type
        sqlite_path: Path for SQLite database
        reinit: Force reinitialization

    Returns:
        Database instance
    """
    global _database
    if _database is None or reinit:
        _database = Database(engine=engine, sqlite_path=sqlite_path)
        _database.create_tables()
    return _database


def reset_database() -> None:
    """Reset the global database instance."""
    global _database
    _database = None
