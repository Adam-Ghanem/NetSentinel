import sqlite3

DATABASE_NAME = "netsentinel.db"

def create_connection():
    """ Create a database connection to the SQLite database """
    conn = None
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        return conn
    except sqlite3.Error as e:
        print(e)
    return conn

def create_tables(conn):
    """ Create tables for packets, connections, alerts, cases, ioc_cache, and users """
    try:
        cursor = conn.cursor()
        
        # Packets table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_mac TEXT,
                dest_mac TEXT,
                source_ip TEXT,
                dest_ip TEXT,
                protocol TEXT,
                source_port INTEGER,
                dest_port INTEGER,
                packet_size INTEGER,
                tcp_flags TEXT,
                dns_query TEXT,
                http_host TEXT,
                http_path TEXT
            );
        """)
        
        # Connections table (Zeek-like)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                conn_id TEXT UNIQUE NOT NULL,
                source_ip TEXT NOT NULL,
                dest_ip TEXT NOT NULL,
                source_port INTEGER,
                dest_port INTEGER,
                protocol TEXT,
                service_guess TEXT,
                duration REAL,
                bytes_sent INTEGER,
                bytes_received INTEGER,
                connection_state TEXT
            );
        """)
        
        # Alerts table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT UNIQUE NOT NULL,
                timestamp TEXT NOT NULL,
                source_ip TEXT,
                dest_ip TEXT,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                recommended_action TEXT,
                mitre_attack TEXT
            );
        """)
        
        # Cases table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT UNIQUE NOT NULL,
                alert_id TEXT,
                title TEXT NOT NULL,
                analyst_notes TEXT,
                status TEXT NOT NULL DEFAULT 'Open',
                severity TEXT,
                tags TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (alert_id) REFERENCES alerts(alert_id)
            );
        """)
        
        # IOC Cache table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ioc_cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator TEXT UNIQUE NOT NULL,
                type TEXT NOT NULL,
                last_checked TEXT NOT NULL,
                data TEXT
            );
        """)
        
        # Users table for dashboard login
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'Analyst'
            );
        """)
        
        conn.commit()
    except sqlite3.Error as e:
        print(e)

if __name__ == '__main__':
    conn = create_connection()
    if conn:
        create_tables(conn)
        conn.close()
        print("Database and tables created successfully.")
