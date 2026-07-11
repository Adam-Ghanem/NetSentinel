import datetime

import bcrypt
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text, create_engine, func, text
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

from app.config import Config

Base = declarative_base()


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc)


class PacketModel(Base):
    __tablename__ = 'packets'
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime(timezone=True), default=utc_now, index=True)
    source_mac = Column(String)
    dest_mac = Column(String)
    source_ip = Column(String, index=True)
    dest_ip = Column(String, index=True)
    protocol = Column(String)
    source_port = Column(Integer)
    dest_port = Column(Integer)
    packet_size = Column(Integer)
    tcp_flags = Column(String)
    arp_op = Column(String)
    dns_query = Column(String)
    http_host = Column(String)
    http_path = Column(String)
    payload_raw = Column(Text)
    payload_printable = Column(Text)
    tls_version = Column(String)
    ja3_hash = Column(String, index=True)


class AlertModel(Base):
    __tablename__ = 'alerts'
    id = Column(Integer, primary_key=True)
    alert_id = Column(String, unique=True, nullable=False)
    timestamp = Column(DateTime(timezone=True), default=utc_now, index=True)
    source_ip = Column(String, index=True)
    dest_ip = Column(String, index=True)
    alert_type = Column(String, nullable=False, index=True)
    severity = Column(String, nullable=False, index=True)
    description = Column(Text)
    recommended_action = Column(Text)
    mitre_attack = Column(String)


class CaseModel(Base):
    __tablename__ = 'cases'
    id = Column(Integer, primary_key=True)
    case_id = Column(String, unique=True, nullable=False)
    alert_id = Column(String, ForeignKey('alerts.alert_id'))
    title = Column(String, nullable=False)
    analyst_notes = Column(Text)
    status = Column(String, default='Open', index=True)
    severity = Column(String, index=True)
    tags = Column(String)
    created_at = Column(DateTime(timezone=True), default=utc_now)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)
    alert = relationship("AlertModel")


class UserModel(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    role = Column(String, default='Analyst')


class IocCacheModel(Base):
    __tablename__ = "ioc_cache"
    id = Column(Integer, primary_key=True)
    indicator = Column(String, unique=True, nullable=False, index=True)
    type = Column(String, nullable=False)
    data = Column(Text, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)


class DatabaseManager:
    def __init__(self, db_url=None):
        self.db_url = db_url or Config.DATABASE_URL
        self.engine = create_engine(self.db_url)
        Base.metadata.create_all(self.engine)
        self._apply_sqlite_schema_updates()
        self.Session = sessionmaker(bind=self.engine, expire_on_commit=False)

    def _apply_sqlite_schema_updates(self):
        """Add newly introduced columns when an older local SQLite database already exists."""
        if not self.db_url.startswith("sqlite"):
            return

        required_packet_columns = {
            "payload_raw": "TEXT",
            "payload_printable": "TEXT",
            "tls_version": "VARCHAR",
            "ja3_hash": "VARCHAR",
            "arp_op": "VARCHAR",
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

    def get_session(self):
        return self.Session()

    def add_packet(self, packet_data):
        session = self.get_session()
        try:
            packet = PacketModel(**packet_data)
            session.add(packet)
            session.commit()
            return packet
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def get_packets(self, limit=100):
        session = self.get_session()
        try:
            return session.query(PacketModel).order_by(PacketModel.timestamp.desc()).limit(limit).all()
        finally:
            session.close()

    def insert_alert(self, alert_data):
        session = self.get_session()
        try:
            alert = AlertModel(**alert_data)
            session.add(alert)
            session.commit()
            return alert
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def get_alerts(self, limit=100):
        session = self.get_session()
        try:
            return session.query(AlertModel).order_by(AlertModel.timestamp.desc()).limit(limit).all()
        finally:
            session.close()

    def get_all_cases(self):
        session = self.get_session()
        try:
            return session.query(CaseModel).all()
        finally:
            session.close()

    def insert_case(self, case_data):
        session = self.get_session()
        try:
            case = CaseModel(**case_data)
            session.add(case)
            session.commit()
            return case
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def update_case(self, case_id, updates):
        allowed_fields = {"title", "analyst_notes", "status", "severity", "tags"}
        session = self.get_session()
        try:
            case = session.query(CaseModel).filter_by(case_id=case_id).first()
            if case is None:
                return None
            for field, value in updates.items():
                if field in allowed_fields:
                    setattr(case, field, value)
            case.updated_at = utc_now()
            session.commit()
            return case
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def get_ioc_cache(self, indicator):
        session = self.get_session()
        try:
            return session.query(IocCacheModel).filter_by(indicator=indicator).first()
        finally:
            session.close()

    def insert_ioc_cache(self, cache_data):
        session = self.get_session()
        try:
            entry = session.query(IocCacheModel).filter_by(
                indicator=cache_data["indicator"]
            ).first()
            if entry is None:
                entry = IocCacheModel(**cache_data)
                session.add(entry)
            else:
                entry.type = cache_data["type"]
                entry.data = cache_data["data"]
                entry.updated_at = utc_now()
            session.commit()
            return entry
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def count_packets(self):
        session = self.get_session()
        try:
            return session.query(func.count(PacketModel.id)).scalar() or 0
        finally:
            session.close()

    def count_alerts(self, severity=None):
        session = self.get_session()
        try:
            query = session.query(func.count(AlertModel.id))
            if severity:
                query = query.filter(AlertModel.severity == severity)
            return query.scalar() or 0
        finally:
            session.close()

    def create_user(self, username, password, role='Analyst'):
        session = self.get_session()
        try:
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            user = UserModel(username=username, password_hash=password_hash, role=role)
            session.add(user)
            session.commit()
            return user
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def authenticate_user(self, username, password):
        session = self.get_session()
        try:
            user = session.query(UserModel).filter_by(username=username).first()
            if user and bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
                return user
            return None
        finally:
            session.close()
