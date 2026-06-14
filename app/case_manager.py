import uuid
from app.utils import get_timestamp

class CaseManager:
    def __init__(self, database_manager):
        self.database_manager = database_manager

    def create_case_from_alert(self, alert_id, title, analyst_notes="", severity="Medium", tags=""):
        case_id = str(uuid.uuid4())
        created_at = get_timestamp()
        updated_at = get_timestamp()
        case_data = {
            "case_id": case_id,
            "alert_id": alert_id,
            "title": title,
            "analyst_notes": analyst_notes,
            "status": "Open",
            "severity": severity,
            "tags": tags,
            "created_at": created_at,
            "updated_at": updated_at
        }
        self.database_manager.insert_case(case_data)
        return case_data

    def update_case_status(self, case_id, status):
        updated_at = get_timestamp()
        self.database_manager.update_case(case_id, {"status": status, "updated_at": updated_at})

    def add_analyst_notes(self, case_id, notes):
        updated_at = get_timestamp()
        self.database_manager.update_case(case_id, {"analyst_notes": notes, "updated_at": updated_at})

    def get_case(self, case_id):
        return self.database_manager.get_case(case_id)

    def get_all_cases(self):
        return self.database_manager.get_all_cases()

if __name__ == '__main__':
    # Dummy DatabaseManager for testing
    class MockDatabaseManager:
        def __init__(self):
            self.cases = {}
            self.alerts = {"alert-123": {"alert_id": "alert-123", "source_ip": "1.1.1.1"}}

        def insert_case(self, case_data):
            print(f"[Mock DB] Inserting case: {case_data["title"]}")
            self.cases[case_data["case_id"]] = case_data

        def update_case(self, case_id, updates):
            if case_id in self.cases:
                self.cases[case_id].update(updates)
                print(f"[Mock DB] Updated case {case_id}: {updates}")

        def get_case(self, case_id):
            return self.cases.get(case_id)

        def get_all_cases(self):
            return list(self.cases.values())

        def insert_alert(self, alert):
            self.alerts[alert["alert_id"]] = alert

        def get_alert(self, alert_id):
            return self.alerts.get(alert_id)


    mock_db = MockDatabaseManager()
    case_manager = CaseManager(mock_db)

    # Create a case
    new_case = case_manager.create_case_from_alert("alert-123", "Suspicious Activity on Host 1.1.1.1", severity="High")
    print(f"\nCreated Case: {new_case}")

    # Update case status
    case_manager.update_case_status(new_case["case_id"], "Investigating")
    updated_case = case_manager.get_case(new_case["case_id"])
    print(f"\nUpdated Case: {updated_case}")

    # Add analyst notes
    case_manager.add_analyst_notes(new_case["case_id"], "Initial investigation shows multiple failed login attempts.")
    updated_case_with_notes = case_manager.get_case(new_case["case_id"])
    print(f"\nCase with Notes: {updated_case_with_notes}")

    # Get all cases
    all_cases = case_manager.get_all_cases()
    print(f"\nAll Cases: {all_cases}")
