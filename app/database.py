import datetime
from contextlib import contextmanager
from pathlib import Path

import bcrypt
from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, String, Text, create_engine, event, text
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

from app.config import Config

Base = declarative_base()


class PacketModel(Base):
    __tablename__ = "packets"
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)
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
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)
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
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    alert = relationship("AlertModel")


class UserModel(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    role = Column(String, default="Analyst")


class DatabaseManager:
    """Own database initialization and short-lived transactional sessions."""

    def __init__(self, db_url=None):
        self.db_url = db_url or Config.DATABASE_URL
        self.engine = create_engine(self.db_url, pool_pre_ping=True)
        self._configure_sqlite()
        Base.metadata.create_all(self.engine)
        self._apply_sqlite_schema_updates()
        self.Session = sessionmaker(bind=self.engine, expire_on_commit=False)

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
        """Add newly introduced columns when an older local SQLite database already exists."""
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
                row[1] for row in connection.execute(text("PRAGMA table_info(packets)"))
            }
            for column_name, column_type in required_packet_columns.items():
                if column_name not in existing_columns:
                    connection.execute(
                        text(f"ALTER TABLE packets ADD COLUMN {column_name} {column_type}")
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

    def add_packet(self, packet_data):
        with self.transaction() as session:
            packet = PacketModel(**packet_data)
            session.add(packet)
        return packet

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

    def get_all_cases(self):
        with self.Session() as session:
            return session.query(CaseModel).all()

    def create_user(self, username, password, role="Analyst"):
        username = username.strip()
        if not username:
            raise ValueError("username must not be empty")
        if not password:
            raise ValueError("password must not be empty")

        password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        with self.transaction() as session:
            user = UserModel(username=username, password_hash=password_hash, role=role)
            session.add(user)
        return user

    def authenticate_user(self, username, password):
        with self.Session() as session:
            user = session.query(UserModel).filter_by(username=username.strip()).first()
            if user and bcrypt.checkpw(password.encode("utf-8"), user.password_hash.encode("utf-8")):
                return user
            return None

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
