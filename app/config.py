import os

class Config:
    DATABASE_NAME = os.getenv("DATABASE_NAME", "netsentinel.db")
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", None)
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", None)
    # Add other configuration variables here as needed

