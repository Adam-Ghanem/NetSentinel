import uuid

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text

from app.database import Base, CaseAuditEventModel, CaseModel, _utcnow_naive

_MAX_EVIDENCE_TYPE_LENGTH = 64
_MAX_SOURCE_LENGTH = 256
_MAX_REFERENCE_LENGTH = 512
_MAX_SUMMARY_LENGTH = 2_000
_MAX_ACTOR_LENGTH = 128


class CaseEvidenceModel(Base):
    __tablename__ = "case_evidence"

    id = Column(Integer, primary_key=True)
    evidence_id = Column(String, unique=True, nullable=False)
    case_id = Column(String, ForeignKey("cases.case_id"), nullable=False, index=True)
    evidence_type = Column(String(_MAX_EVIDENCE_TYPE_LENGTH), nullable=False, index=True)
    source = Column(String(_MAX_SOURCE_LENGTH), nullable=False)
    reference = Column(String(_MAX_REFERENCE_LENGTH), nullable=False)
    summary = Column(Text, nullable=False, default="")
    added_by = Column(String(_MAX_ACTOR_LENGTH), nullable=False, index=True)
    created_at = Column(DateTime, default=_utcnow_naive, nullable=False, index=True)


class CaseEvidenceStore:
    def __init__(self, database_manager):
        self.db = database_manager

    def add(self, case_id, evidence_data, event_data):
        with self.db.transaction() as session:
            case = session.query(CaseModel).filter_by(case_id=case_id).first()
            if case is None:
                return None
            evidence = CaseEvidenceModel(**evidence_data)
            session.add(evidence)
            session.flush()
            session.add(CaseAuditEventModel(**event_data))
        return evidence

    def list_for_case(self, case_id, limit=500):
        limit = self._validate_limit(limit)
        with self.db.Session() as session:
            return (
                session.query(CaseEvidenceModel)
                .filter_by(case_id=case_id)
                .order_by(CaseEvidenceModel.created_at.asc(), CaseEvidenceModel.id.asc())
                .limit(limit)
                .all()
            )

    @staticmethod
    def new_evidence_id():
        return str(uuid.uuid4())

    @staticmethod
    def _validate_limit(limit):
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise TypeError("limit must be an integer")
        if not 1 <= limit <= 10_000:
            raise ValueError("limit must be between 1 and 10000")
        return limit
