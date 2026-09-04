import datetime
from contextlib import contextmanager
from pathlib import Path

import bcrypt
from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
    event,
    inspect,
    text,
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

from app.config import Config

Base = declarative_base()

_CASE_UPDATE_FIELDS = frozenset(
    {"title", "analyst_notes", "status", "severity", "tags", "owner"}
)
_CASE_METRIC_STATUSES = ("Closed", "In Progress", "Open", "Resolved")


def _utcnow_naive():
    """Return UTC as a naive datetime for the existing database storage contract."""
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


class PacketModel(Base):
    __tablename__ = "packets"
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=_utcnow_naive, index=True)
    source_mac = Column(String)
    dest_mac = Column(String)
    source_ip = Column(String, index=True)
    dest_ip = Column(String, index=True)
    protocol = Column(String)
    source_port = Column(Integer)
    dest_port = Column(Integer)
    packet_size = Column(Integer)
    tcp_flags = Column(String)
    dns_query = Column(String)
    http_host = Column(String)
    http_path = Column(String)
    payload_raw = Column(Text)
    payload_printable = Column(Text)
    tls_version = Column(String)
    ja3_hash = Column(String, index=True)


class AlertModel(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True)
    alert_id = Column(String, unique=True, nullable=False)
    timestamp = Column(DateTime, default=_utcnow_naive, index=True)
    source_ip = Column(String, index=True)
    dest_ip = Column(String, index=True)
    alert_type = Column(String, nullable=False, index=True)
    severity = Column(String, nullable=False, index=True)
    description = Column(Text)
    recommended_action = Column(Text)
    mitre_attack = Column(String)


class CaseModel(Base):
    __tablename__ = "cases"
    id = Column(Integer, primary_key=True)
    case_id = Column(String, unique=True, nullable=False)
    alert_id = Column(String, ForeignKey("alerts.alert_id"))
    title = Column(String, nullable=False)
    analyst_notes = Column(Text)
    status = Column(String, default="Open", index=True)
    severity = Column(String, index=True)
    tags = Column(String)
    owner = Column(String(128), nullable=True, index=True)
    created_at = Column(DateTime, default=_utcnow_naive)
    updated_at = Column(
        DateTime,
        default=_utcnow_naive,
        onupdate=_utcnow_naive,
    )
    alert = relationship("AlertModel")


class CaseAuditEventModel(Base):
    __tablename__ = "case_audit_events"
    id = Column(Integer, primary_key=True)
    event_id = Column(String, unique=True, nullable=False)
    case_id = Column(String, ForeignKey("cases.case_id"), nullable=False, index=True)
    event_type = Column(String(64), nullable=False, index=True)
    actor = Column(String(128), nullable=False, index=True)
    previous_value = Column(String(512), nullable=False, default="")
    new_value = Column(String(512), nullable=False, default="")
    created_at = Column(DateTime, default=_utcnow_naive, nullable=False, index=True)


class CaseEvidenceModel(Base):
    __tablename__ = "case_evidence"
    id = Column(Integer, primary_key=True)
    evidence_id = Column(String, unique=True, nullable=False)
    case_id = Column(String, ForeignKey("cases.case_id"), nullable=False, index=True)
    evidence_type = Column(String(64), nullable=False, index=True)
    reference = Column(String(2048), nullable=False)
    sha256 = Column(String(64), nullable=True, index=True)
    added_by = Column(String(128), nullable=False, index=True)
    created_at = Column(DateTime, default=_utcnow_naive, nullable=False, index=True)


class UserModel(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    role = Column(String, default="Analyst")


class DatabaseManager:
    """Own database connections and short-lived transactional sessions."""

    def __init__(self, db_url=None, auto_create_schema=None):
        self.db_url = db_url or Config.DATABASE_URL
        self.auto_create_schema = (
            Config.AUTO_CREATE_SCHEMA
            if auto_create_schema is None
            else auto_create_schema
        )
        if Config.ENVIRONMENT == "production" and self.auto_create_schema:
            raise RuntimeError(
                "schema auto-creation is disabled in production; run Alembic migrations"
            )

        self.engine = create_engine(self.db_url, pool_pre_ping=True)
        self._configure_sqlite()
        if self.auto_create_schema:
            self.bootstrap_schema()
        self.Session = sessionmaker(bind=self.engine, expire_on_commit=False)

    def bootstrap_schema(self):
        """Create local-development schema explicitly; never use for production."""
        Base.metadata.create_all(self.engine)
        self._apply_sqlite_schema_updates()

    def _configure_sqlite(self):
        if not self.db_url.startswith("sqlite"):
            return

        @event.listens_for(self.engine, "connect")
        def set_sqlite_pragmas(dbapi_connection, _connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA busy_timeout=5000")
            if self.db_url != "sqlite:///:memory:":
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.close()

    def _apply_sqlite_schema_updates(self):
        """Add newly introduced columns to older local SQLite databases."""
        if not self.db_url.startswith("sqlite"):
            return

        required_packet_columns = {
            "payload_raw": "TEXT",
            "payload_printable": "TEXT",
            "tls_version": "VARCHAR",
            "ja3_hash": "VARCHAR",
        }

        with self.engine.begin() as connection:
            existing_columns = {
                row[1]
                for row in connection.execute(text("PRAGMA table_info(packets)"))
            }
            for column_name, column_type in required_packet_columns.items():
                if column_name not in existing_columns:
                    connection.execute(
                        text(f"ALTER TABLE packets ADD COLUMN {column_name} {column_type}")
                    )

            existing_case_columns = {
                row[1]
                for row in connection.execute(text("PRAGMA table_info(cases)"))
            }
            if "owner" not in existing_case_columns:
                connection.execute(text("ALTER TABLE cases ADD COLUMN owner VARCHAR(128)"))
                connection.execute(
                    text("CREATE INDEX IF NOT EXISTS ix_cases_owner ON cases (owner)")
                )

    @contextmanager
    def transaction(self):
        """Commit on success, rollback on failure, and always close the session."""
        session = self.Session()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def database_health(self):
        """Return deterministic connectivity, schema, and integrity diagnostics."""
        expected_tables = set(Base.metadata.tables)
        report = {
            "status": "healthy",
            "dialect": self.engine.dialect.name,
            "connectivity": "ok",
            "schema": "ok",
            "missing_tables": [],
        }

        try:
            with self.engine.connect() as connection:
                connection.execute(text("SELECT 1"))
                if self.engine.dialect.name == "sqlite":
                    integrity = connection.execute(text("PRAGMA integrity_check")).scalar_one()
                    report["integrity"] = integrity
                    if str(integrity).lower() != "ok":
                        report["status"] = "degraded"
        except Exception as exc:
            report.update(
                {
                    "status": "unhealthy",
                    "connectivity": "failed",
                    "error": type(exc).__name__,
                }
            )
            return report

        existing_tables = set(inspect(self.engine).get_table_names())
        missing_tables = sorted(expected_tables - existing_tables)
        if missing_tables:
            report.update(
                {
                    "status": "degraded",
                    "schema": "incomplete",
                    "missing_tables": missing_tables,
                }
            )

        return report

    def add_packet(self, packet_data):
        with self.transaction() as session:
            packet = PacketModel(**packet_data)
            session.add(packet)
        return packet

    def add_packets(self, packet_batch):
        if not packet_batch:
            return []

        packets = [PacketModel(**packet_data) for packet_data in packet_batch]
        with self.transaction() as session:
            session.add_all(packets)
        return packets

    def get_packets(self, limit=100):
        limit = self._validate_limit(limit)
        with self.Session() as session:
            return (
                session.query(PacketModel)
                .order_by(PacketModel.timestamp.desc())
                .limit(limit)
                .all()
            )

    def insert_alert(self, alert_data):
        with self.transaction() as session:
            alert = AlertModel(**alert_data)
            session.add(alert)
        return alert

    def get_alerts(self, limit=100):
        limit = self._validate_limit(limit)
        with self.Session() as session:
            return (
                session.query(AlertModel)
                .order_by(AlertModel.timestamp.desc())
                .limit(limit)
                .all()
            )

    def insert_case(self, case_data):
        with self.transaction() as session:
            case = CaseModel(**case_data)
            session.add(case)
        return case

    def insert_case_with_event(self, case_data, event_data):
        with self.transaction() as session:
            case = CaseModel(**case_data)
            session.add(case)
            session.flush()
            event_model = CaseAuditEventModel(**event_data)
            session.add(event_model)
        return case

    def get_case(self, case_id):
        with self.Session() as session:
            return session.query(CaseModel).filter_by(case_id=case_id).first()

    def update_case(self, case_id, updates):
        unsupported = sorted(set(updates) - _CASE_UPDATE_FIELDS)
        if unsupported:
            fields = ", ".join(unsupported)
            raise ValueError(f"unsupported case update fields: {fields}")

        with self.transaction() as session:
            case = session.query(CaseModel).filter_by(case_id=case_id).first()
            if case is None:
                return None
            for field, value in updates.items():
                setattr(case, field, value)
            case.updated_at = _utcnow_naive()
        return case

    def update_case_with_event(self, case_id, updates, event_data):
        unsupported = sorted(set(updates) - _CASE_UPDATE_FIELDS)
        if unsupported:
            fields = ", ".join(unsupported)
            raise ValueError(f"unsupported case update fields: {fields}")

        with self.transaction() as session:
            case = session.query(CaseModel).filter_by(case_id=case_id).first()
            if case is None:
                return None
            for field, value in updates.items():
                setattr(case, field, value)
            case.updated_at = _utcnow_naive()
            session.add(CaseAuditEventModel(**event_data))
        return case

    def insert_case_evidence(self, evidence_data):
        with self.transaction() as session:
            evidence = CaseEvidenceModel(**evidence_data)
            session.add(evidence)
        return evidence

    def insert_case_evidence_with_event(self, evidence_data, event_data):
        with self.transaction() as session:
            evidence = CaseEvidenceModel(**evidence_data)
            session.add(evidence)
            session.add(CaseAuditEventModel(**event_data))
        return evidence

    def get_case_evidence(self, case_id, limit=500, evidence_type=None):
        limit = self._validate_limit(limit)
        with self.Session() as session:
            query = session.query(CaseEvidenceModel).filter_by(case_id=case_id)
            if evidence_type is not None:
                query = query.filter_by(evidence_type=evidence_type)
            return (
                query.order_by(
                    CaseEvidenceModel.created_at.asc(),
                    CaseEvidenceModel.id.asc(),
                )
                .limit(limit)
                .all()
            )

    def get_case_history(self, case_id, limit=500):
        limit = self._validate_limit(limit)
        with self.Session() as session:
            return (
                session.query(CaseAuditEventModel)
                .filter_by(case_id=case_id)
                .order_by(CaseAuditEventModel.created_at.asc(), CaseAuditEventModel.id.asc())
                .limit(limit)
                .all()
            )

    def case_workflow_metrics(self):
        """Return aggregate-only case workflow counts without analyst or evidence values."""
        with self.Session() as session:
            total_cases = session.query(CaseModel).count()
            owned_cases = session.query(CaseModel).filter(CaseModel.owner.is_not(None)).count()
            status_counts = {
                status: session.query(CaseModel).filter_by(status=status).count()
                for status in _CASE_METRIC_STATUSES
            }
            audit_events = session.query(CaseAuditEventModel).count()

        return {
            "total_cases": total_cases,
            "owned_cases": owned_cases,
            "unowned_cases": total_cases - owned_cases,
            "status_counts": status_counts,
            "audit_events": audit_events,
        }

    def get_all_cases(self):
        with self.Session() as session:
            return session.query(CaseModel).order_by(CaseModel.updated_at.desc()).all()

    def create_user(self, username, password, role="Analyst"):
        username = username.strip()
        if not username:
            raise ValueError("username must not be empty")
        if not password:
            raise ValueError("password must not be empty")

        password_hash = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt(),
        ).decode("utf-8")
        with self.transaction() as session:
            user = UserModel(username=username, password_hash=password_hash, role=role)
            session.add(user)
        return user

    def authenticate_user(self, username, password):
        with self.Session() as session:
            user = session.query(UserModel).filter_by(username=username.strip()).first()
            valid_password = user and bcrypt.checkpw(
                password.encode("utf-8"),
                user.password_hash.encode("utf-8"),
            )
            return user if valid_password else None

    def sqlite_database_path(self):
        """Return the local SQLite path, or None for memory/non-SQLite databases."""
        prefix = "sqlite:///"
        if not self.db_url.startswith(prefix) or self.db_url == "sqlite:///:memory:":
            return None
        return Path(self.db_url.removeprefix(prefix)).expanduser().resolve()

    @staticmethod
    def _validate_limit(limit):
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise TypeError("limit must be an integer")
        if not 1 <= limit <= 10_000:
            raise ValueError("limit must be between 1 and 10000")
        return limit
