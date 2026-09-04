import re
import uuid


_ALLOWED_STATUSES = frozenset({"Open", "In Progress", "Resolved", "Closed"})
_MAX_TITLE_LENGTH = 200
_MAX_NOTE_LENGTH = 10_000
_MAX_OWNER_LENGTH = 128
_MAX_ACTOR_LENGTH = 128
_MAX_EVIDENCE_TYPE_LENGTH = 64
_MAX_EVIDENCE_REFERENCE_LENGTH = 2048
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class CaseManager:
    def __init__(self, database_manager):
        self.db = database_manager

    def create_case_from_alert(
        self,
        alert_data,
        title,
        analyst_notes="",
        tags="",
        actor="system",
    ):
        alert_id = str(alert_data.get("alert_id") or "").strip()
        if not alert_id:
            raise ValueError("alert_id must not be empty")

        normalized_title = str(title).strip()
        if not normalized_title:
            raise ValueError("title must not be empty")
        if len(normalized_title) > _MAX_TITLE_LENGTH:
            raise ValueError(f"title must be at most {_MAX_TITLE_LENGTH} characters")

        normalized_notes = self._validate_notes(analyst_notes)
        normalized_actor = self._validate_actor(actor)
        case_id = str(uuid.uuid4())
        case_data = {
            "case_id": case_id,
            "alert_id": alert_id,
            "title": normalized_title,
            "analyst_notes": normalized_notes,
            "status": "Open",
            "severity": alert_data.get("severity"),
            "tags": str(tags).strip(),
        }
        event_data = self._event(
            case_id,
            "case.created",
            normalized_actor,
            "",
            "Open",
        )
        return self.db.insert_case_with_event(case_data, event_data)

    def update_case_status(self, case_id, status, actor="system"):
        if status not in _ALLOWED_STATUSES:
            allowed = ", ".join(sorted(_ALLOWED_STATUSES))
            raise ValueError(f"status must be one of: {allowed}")
        case = self.db.get_case(case_id)
        if case is None:
            return None
        if case.status == status:
            return case
        event_data = self._event(
            case_id,
            "case.status_changed",
            self._validate_actor(actor),
            str(case.status or ""),
            status,
        )
        return self.db.update_case_with_event(case_id, {"status": status}, event_data)

    def assign_owner(self, case_id, owner, actor="system"):
        case = self.db.get_case(case_id)
        if case is None:
            return None
        if owner is None:
            normalized_owner = None
        else:
            normalized_owner = str(owner).strip()
            if not normalized_owner:
                normalized_owner = None
            elif len(normalized_owner) > _MAX_OWNER_LENGTH:
                raise ValueError(f"owner must be at most {_MAX_OWNER_LENGTH} characters")
        if case.owner == normalized_owner:
            return case
        event_data = self._event(
            case_id,
            "case.owner_changed",
            self._validate_actor(actor),
            str(case.owner or ""),
            str(normalized_owner or ""),
        )
        return self.db.update_case_with_event(case_id, {"owner": normalized_owner}, event_data)

    def add_analyst_notes(self, case_id, notes, actor="system"):
        normalized_notes = self._validate_notes(notes)
        case = self.db.get_case(case_id)
        if case is None:
            return None

        existing = str(case.analyst_notes or "").strip()
        combined = f"{existing}\n{normalized_notes}" if existing else normalized_notes
        if len(combined) > _MAX_NOTE_LENGTH:
            raise ValueError(f"analyst notes must be at most {_MAX_NOTE_LENGTH} characters")
        event_data = self._event(
            case_id,
            "case.note_added",
            self._validate_actor(actor),
            "",
            f"length={len(normalized_notes)}",
        )
        return self.db.update_case_with_event(
            case_id,
            {"analyst_notes": combined},
            event_data,
        )

    def add_evidence(
        self,
        case_id,
        evidence_type,
        reference,
        actor="system",
        sha256=None,
    ):
        case = self.db.get_case(case_id)
        if case is None:
            return None

        normalized_type = self._validate_evidence_type(evidence_type)
        normalized_reference = str(reference or "").strip()
        if not normalized_reference:
            raise ValueError("reference must not be empty")
        if len(normalized_reference) > _MAX_EVIDENCE_REFERENCE_LENGTH:
            raise ValueError(
                f"reference must be at most {_MAX_EVIDENCE_REFERENCE_LENGTH} characters"
            )

        normalized_sha256 = None
        if sha256 is not None:
            normalized_sha256 = str(sha256).strip().lower()
            if not _SHA256_PATTERN.fullmatch(normalized_sha256):
                raise ValueError("sha256 must be exactly 64 hexadecimal characters")

        actor_value = self._validate_actor(actor)
        evidence_id = str(uuid.uuid4())
        evidence_data = {
            "evidence_id": evidence_id,
            "case_id": case_id,
            "evidence_type": normalized_type,
            "reference": normalized_reference,
            "sha256": normalized_sha256,
            "added_by": actor_value,
        }
        event_data = self._event(
            case_id,
            "case.evidence_added",
            actor_value,
            "",
            (
                f"evidence_id={evidence_id};type={normalized_type};"
                f"sha256={'yes' if normalized_sha256 else 'no'}"
            ),
        )
        return self.db.insert_case_evidence_with_event(evidence_data, event_data)

    def get_case(self, case_id):
        return self.db.get_case(case_id)

    def get_case_history(self, case_id, limit=500):
        return self.db.get_case_history(case_id, limit=limit)

    def get_case_evidence(self, case_id, limit=500, evidence_type=None):
        normalized_type = (
            self._validate_evidence_type(evidence_type)
            if evidence_type is not None
            else None
        )
        return self.db.get_case_evidence(
            case_id,
            limit=limit,
            evidence_type=normalized_type,
        )

    def get_all_cases(self):
        return self.db.get_all_cases()

    @staticmethod
    def _validate_notes(notes):
        normalized = str(notes).strip()
        if len(normalized) > _MAX_NOTE_LENGTH:
            raise ValueError(f"analyst notes must be at most {_MAX_NOTE_LENGTH} characters")
        return normalized

    @staticmethod
    def _validate_actor(actor):
        normalized = str(actor or "").strip()
        if not normalized:
            raise ValueError("actor must not be empty")
        if len(normalized) > _MAX_ACTOR_LENGTH:
            raise ValueError(f"actor must be at most {_MAX_ACTOR_LENGTH} characters")
        return normalized

    @staticmethod
    def _validate_evidence_type(evidence_type):
        normalized = str(evidence_type or "").strip()
        if not normalized:
            raise ValueError("evidence_type must not be empty")
        if len(normalized) > _MAX_EVIDENCE_TYPE_LENGTH:
            raise ValueError(
                f"evidence_type must be at most {_MAX_EVIDENCE_TYPE_LENGTH} characters"
            )
        return normalized

    @staticmethod
    def _event(case_id, event_type, actor, previous_value, new_value):
        return {
            "event_id": str(uuid.uuid4()),
            "case_id": case_id,
            "event_type": event_type,
            "actor": actor,
            "previous_value": previous_value,
            "new_value": new_value,
        }
