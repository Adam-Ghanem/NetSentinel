from sqlalchemy import create_engine, Column, Integer, String, Float, Text, ForeignKey, DateTime, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
import datetime
import uuid
import bcrypt
from app.config import Config

Base = declarative_base()

class PacketModel(Base):
    __tablename__ = 'packets'
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

class ConnectionModel(Base):
    __tablename__ = 'connections'
    id = Column(Integer, primary_key=True)
    conn_id = Column(String, unique=True, nullable=False)
    source_ip = Column(String, nullable=False, index=True)
    dest_ip = Column(String, nullable=False, index=True)
    source_port = Column(Integer)
    dest_port = Column(Integer)
    protocol = Column(String)
    service_guess = Column(String)
    duration = Column(Float)
    bytes_sent = Column(Integer)
    bytes_received = Column(Integer)
    connection_state = Column(String)

class AlertModel(Base):
    __tablename__ = 'alerts'
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
    __tablename__ = 'cases'
    id = Column(Integer, primary_key=True)
    case_id = Column(String, unique=True, nullable=False)
    alert_id = Column(String, ForeignKey('alerts.alert_id'))
    title = Column(String, nullable=False)
    analyst_notes = Column(Text)
    status = Column(String, default='Open', index=True)
    severity = Column(String, index=True)
    tags = Column(String)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    alert = relationship("AlertModel")

class IOCCacheModel(Base):
    __tablename__ = 'ioc_cache'
    id = Column(Integer, primary_key=True)
    indicator = Column(String, unique=True, nullable=False, index=True)
    type = Column(String, nullable=False)
    last_checked = Column(DateTime, default=datetime.datetime.utcnow)
    data = Column(Text)

class UserModel(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    role = Column(String, default='Analyst')

class DatabaseManager:
    def __init__(self, db_url=None):
        self.db_url = db_url or Config.DATABASE_URL
        self.engine = create_engine(self.db_url)
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)

    def get_session(self):
        return self.Session()

    # Packet Methods
    def add_packet(self, packet_data):
        session = self.get_session()
        try:
            packet = PacketModel(**packet_data)
            session.add(packet)
            session.commit()
            return packet
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()

    def get_packets(self, limit=100):
        session = self.get_session()
        try:
            return session.query(PacketModel).order_by(PacketModel.timestamp.desc()).limit(limit).all()
        finally:
            session.close()

    # Alert Methods
    def insert_alert(self, alert_data):
        session = self.get_session()
        try:
            alert = AlertModel(**alert_data)
            session.add(alert)
            session.commit()
            return alert
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()

    def get_alerts(self, limit=100):
        session = self.get_session()
        try:
            return session.query(AlertModel).order_by(AlertModel.timestamp.desc()).limit(limit).all()
        finally:
            session.close()

    # Case Methods
    def insert_case(self, case_data):
        session = self.get_session()
        try:
            if 'id' in case_data: del case_data['id']
            case = CaseModel(**case_data)
            session.add(case)
            session.commit()
            return case
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()

    def get_all_cases(self):
        session = self.get_session()
        try:
            return session.query(CaseModel).all()
        finally:
            session.close()

    def update_case(self, case_id, update_data):
        session = self.get_session()
        try:
            case = session.query(CaseModel).filter_by(case_id=case_id).first()
            if case:
                for key, value in update_data.items():
                    setattr(case, key, value)
                session.commit()
                return case
            return None
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()

    # IOC Cache Methods
    def get_ioc_cache(self, indicator):
        session = self.get_session()
        try:
            return session.query(IOCCacheModel).filter_by(indicator=indicator).first()
        finally:
            session.close()

    def insert_ioc_cache(self, ioc_data):
        session = self.get_session()
        try:
            existing = session.query(IOCCacheModel).filter_by(indicator=ioc_data['indicator']).first()
            if existing:
                for key, value in ioc_data.items():
                    setattr(existing, key, value)
                existing.last_checked = datetime.datetime.utcnow()
            else:
                ioc = IOCCacheModel(**ioc_data)
                session.add(ioc)
            session.commit()
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()

    # User Methods
    def create_user(self, username, password, role='Analyst'):
        session = self.get_session()
        try:
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            user = UserModel(username=username, password_hash=password_hash, role=role)
            session.add(user)
            session.commit()
            return user
        except Exception as e:
            session.rollback()
            raise e
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

if __name__ == '__main__':
    db = DatabaseManager()
    print("Database initialized.")
    # Create default users if they don't exist
    if not db.authenticate_user("admin", "admin"):
        try:
            db.create_user("admin", "admin", role="Admin")
            print("Default admin created.")
        except: pass
    if not db.authenticate_user("analyst", "analyst"):
        try:
            db.create_user("analyst", "analyst", role="Analyst")
            print("Default analyst created.")
        except: pass
