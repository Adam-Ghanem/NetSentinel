import uuid


_ALLOWED_STATUSES = frozenset({"Open", "In Progress", "Resolved", "Closed"})
_MAX_TITLE_LENGTH = 200
_MAX_NOTE_LENGTH = 10_000
_MAX_OWNER_LENGTH = 128


class CaseManager:
    def __init__(self, database_manager):
        self.db = database_manager

    def create_case_from_alert(self, alert_data, title, analyst_notes="", tags=""):
        alert_id = str(alert_data.get("alert_id") or "").strip()
        if not alert_id:
            raise ValueError("alert_id must not be empty")

        normalized_title = str(title).strip()
        if not normalized_title:
            raise ValueError("title must not be empty")
        if len(normalized_title) > _MAX_TITLE_LENGTH:
            raise ValueError(f"title must be at most {_MAX_TITLE_LENGTH} characters")

        normalized_notes = self._validate_notes(analyst_notes)
        case_data = {
            "case_id": str(uuid.uuid4()),
            "alert_id": alert_id,
            "title": normalized_title,
            "analyst_notes": normalized_notes,
            "status": "Open",
            "severity": alert_data.get("severity"),
            "tags": str(tags).strip(),
        }
        return self.db.insert_case(case_data)

    def update_case_status(self, case_id, status):
        if status not in _ALLOWED_STATUSES:
            allowed = ", ".join(sorted(_ALLOWED_STATUSES))
            raise ValueError(f"status must be one of: {allowed}")
        return self.db.update_case(case_id, {"status": status})

    def assign_owner(self, case_id, owner):
        if owner is None:
            normalized_owner = None
        else:
            normalized_owner = str(owner).strip()
            if not normalized_owner:
                normalized_owner = None
            elif len(normalized_owner) > _MAX_OWNER_LENGTH:
                raise ValueError(f"owner must be at most {_MAX_OWNER_LENGTH} characters")
        return self.db.update_case(case_id, {"owner": normalized_owner})

    def add_analyst_notes(self, case_id, notes):
        normalized_notes = self._validate_notes(notes)
        case = self.db.get_case(case_id)
        if case is None:
            return None

        existing = str(case.analyst_notes or "").strip()
        combined = f"{existing}\n{normalized_notes}" if existing else normalized_notes
        if len(combined) > _MAX_NOTE_LENGTH:
            raise ValueError(f"analyst notes must be at most {_MAX_NOTE_LENGTH} characters")
        return self.db.update_case(case_id, {"analyst_notes": combined})

    def get_case(self, case_id):
        return self.db.get_case(case_id)

    def get_all_cases(self):
        return self.db.get_all_cases()

    @staticmethod
    def _validate_notes(notes):
        normalized = str(notes).strip()
        if len(normalized) > _MAX_NOTE_LENGTH:
            raise ValueError(f"analyst notes must be at most {_MAX_NOTE_LENGTH} characters")
        return normalized
