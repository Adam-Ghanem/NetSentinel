import uuid
import datetime

class CaseManager:
    def __init__(self, database_manager):
        self.db = database_manager

    def create_case_from_alert(self, alert_data, title, analyst_notes="", tags=""):
        case_id = str(uuid.uuid4())
        case_data = {
            "case_id": case_id,
            "alert_id": alert_data.get("alert_id"),
            "title": title,
            "analyst_notes": analyst_notes,
            "status": "Open",
            "severity": alert_data.get("severity"),
            "tags": tags,
            "created_at": datetime.datetime.now(datetime.timezone.utc),
            "updated_at": datetime.datetime.now(datetime.timezone.utc),
        }
        return self.db.insert_case(case_data)

    def update_case_status(self, case_id, status):
        return self.db.update_case(case_id, {"status": status})

    def add_analyst_notes(self, case_id, notes):
        return self.db.update_case(case_id, {"analyst_notes": notes})

    def get_case(self, case_id):
        all_cases = self.db.get_all_cases()
        for case in all_cases:
            if case.case_id == case_id:
                return case
        return None

    def get_all_cases(self):
        return self.db.get_all_cases()
