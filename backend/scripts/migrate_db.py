from __future__ import annotations

from pathlib import Path
import sqlite3

def migrate():
    # Database path
    db_path = str(Path(__file__).resolve().parent.parent / "threatlensai.db")
    if not Path(db_path).exists():
        print("Database not found! It will be created when uvicorn starts.")
        return

    print(f"Connecting to database at {db_path}...")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # 1. Add missing columns to malicious_ips
    cursor.execute("PRAGMA table_info(malicious_ips);")
    ip_cols = [col[1] for col in cursor.fetchall()]
    print("malicious_ips columns:", ip_cols)

    if "data_source" not in ip_cols:
        print("Adding data_source to malicious_ips...")
        cursor.execute("ALTER TABLE malicious_ips ADD COLUMN data_source TEXT DEFAULT 'csv_import';")
    if "enriched_at" not in ip_cols:
        print("Adding enriched_at to malicious_ips...")
        cursor.execute("ALTER TABLE malicious_ips ADD COLUMN enriched_at TIMESTAMP;")

    # 2. Add missing columns to malicious_domains
    cursor.execute("PRAGMA table_info(malicious_domains);")
    domain_cols = [col[1] for col in cursor.fetchall()]
    print("malicious_domains columns:", domain_cols)

    if "enriched_at" not in domain_cols:
        print("Adding enriched_at to malicious_domains...")
        cursor.execute("ALTER TABLE malicious_domains ADD COLUMN enriched_at TIMESTAMP;")

    # 3. Add missing columns to cve_vulnerabilities
    cursor.execute("PRAGMA table_info(cve_vulnerabilities);")
    cve_cols = [col[1] for col in cursor.fetchall()]
    print("cve_vulnerabilities columns:", cve_cols)

    if "cvss_v3_score" not in cve_cols:
        print("Adding cvss_v3_score to cve_vulnerabilities...")
        cursor.execute("ALTER TABLE cve_vulnerabilities ADD COLUMN cvss_v3_score REAL;")
    if "cvss_v3_vector" not in cve_cols:
        print("Adding cvss_v3_vector to cve_vulnerabilities...")
        cursor.execute("ALTER TABLE cve_vulnerabilities ADD COLUMN cvss_v3_vector TEXT;")
    if "enriched_at" not in cve_cols:
        print("Adding enriched_at to cve_vulnerabilities...")
        cursor.execute("ALTER TABLE cve_vulnerabilities ADD COLUMN enriched_at TIMESTAMP;")

    # Commit and close
    conn.commit()
    conn.close()
    print("Migration completed successfully.")

if __name__ == "__main__":
    migrate()
