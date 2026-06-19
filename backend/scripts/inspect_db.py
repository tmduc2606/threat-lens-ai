"""
inspect_db.py — Database inspection utility.
Supports both SQLite (default) and PostgreSQL.

Usage:
    SQLite:      python scripts/inspect_db.py
    PostgreSQL:  python scripts/inspect_db.py --postgres postgresql+psycopg2://user:pass@host/db
"""
from __future__ import annotations

import argparse
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def inspect_sqlite(db_path: str):
    import sqlite3
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [row[0] for row in cursor.fetchall()]
    logger.info(f"SQLite tables ({len(tables)}): {tables}")
    for table in tables:
        cursor.execute(f"SELECT COUNT(*) FROM [{table}]")
        count = cursor.fetchone()[0]
        logger.info(f"  {table}: {count} rows")
    conn.close()


def inspect_postgres(url: str):
    import sqlalchemy as sa
    engine = sa.create_engine(url)
    with engine.connect() as conn:
        result = conn.execute(sa.text(
            "SELECT table_name FROM information_schema.tables WHERE table_schema='public'"
        ))
        tables = [row[0] for row in result]
        logger.info(f"PostgreSQL tables ({len(tables)}): {tables}")
        for table in tables:
            result = conn.execute(sa.text(f"SELECT COUNT(*) FROM {sa.quoted_name(table, True)}"))
            count = result.scalar()
            logger.info(f"  {table}: {count} rows")


def main():
    parser = argparse.ArgumentParser(description="Inspect database tables and row counts")
    parser.add_argument("--postgres", help="PostgreSQL connection URL (uses SQLite if not provided)")
    parser.add_argument("--db", default="../threatlensai.db", help="SQLite database path (default: ../threatlensai.db)")
    args = parser.parse_args()

    if args.postgres:
        inspect_postgres(args.postgres)
    else:
        db_path = Path(args.db)
        if not db_path.is_file():
            logger.error(f"SQLite database not found: {db_path}")
            return
        inspect_sqlite(str(db_path))


if __name__ == "__main__":
    main()
