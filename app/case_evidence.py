import uuid

from app.database import (
    CaseAuditEventModel,
    CaseEvidenceModel,
    CaseModel,
)


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
