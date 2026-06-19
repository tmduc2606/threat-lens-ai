"""
migrate_sqlite_to_postgres.py

One-time migration script: reads from SQLite and writes to PostgreSQL.
Usage:
    python scripts/migrate_sqlite_to_postgres.py --sqlite ./threatlensai.db --postgres postgresql+psycopg2://user:pass@host/db

Dry run mode (read-only):
    python scripts/migrate_sqlite_to_postgres.py --sqlite ./threatlensai.db --postgres ... --dry-run
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def _parse_args():
    parser = argparse.ArgumentParser(description="Migrate SQLite data to PostgreSQL")
    parser.add_argument("--sqlite", required=True, help="Path to SQLite database file")
    parser.add_argument("--postgres", required=True, help="PostgreSQL connection URL")
    parser.add_argument("--dry-run", action="store_true", help="Read-only mode: count records without writing")
    return parser.parse_args()


def _connect_sqlite(path: str):
    import sqlalchemy as sa
    engine = sa.create_engine(f"sqlite:///{path}")
    return engine


def _connect_postgres(url: str):
    import sqlalchemy as sa
    engine = sa.create_engine(url)
    return engine


def _get_sqlite_data(engine) -> Dict[str, List[Dict[str, Any]]]:
    """Extract all records from SQLite into dict of table_name -> list of row dicts."""
    import sqlalchemy as sa
    inspector = sa.inspect(engine)
    tables = inspector.get_table_names()
    logger.info(f"Found {len(tables)} tables in SQLite: {tables}")

    data: Dict[str, List[Dict[str, Any]]] = {}
    with engine.connect() as conn:
        for table in tables:
            result = conn.execute(sa.text(f"SELECT * FROM {sa.quoted_name(table, True)}"))
            rows = [dict(r._mapping) for r in result]
            data[table] = rows
            logger.info(f"  {table}: {len(rows)} rows")
    return data


def _create_tables(engine, base):
    """Create all tables in PostgreSQL using SQLAlchemy metadata."""
    base.metadata.create_all(bind=engine)
    logger.info("Tables created in PostgreSQL.")


def _insert_data(engine, tables_data: Dict[str, List[Dict[str, Any]]]):
    """Insert data into PostgreSQL."""
    import sqlalchemy as sa
    from sqlalchemy import inspect as sa_inspect

    inspector = sa_inspect(engine)
    existing_tables = set(inspector.get_table_names())

    with engine.begin() as conn:
        for table_name, rows in tables_data.items():
            if table_name not in existing_tables:
                logger.warning(f"Table {table_name} does not exist in PostgreSQL, skipping.")
                continue
            if not rows:
                logger.info(f"  {table_name}: 0 rows to insert")
                continue

            # Insert in batches
            batch_size = 500
            for i in range(0, len(rows), batch_size):
                batch = rows[i:i + batch_size]
                stmt = sa.text(f"""
                    INSERT INTO {sa.quoted_name(table_name, True)} ({', '.join(batch[0].keys())})
                    VALUES ({', '.join([':' + k for k in batch[0].keys()])})
                    ON CONFLICT DO NOTHING
                """)
                conn.execute(stmt, batch)

            logger.info(f"  {table_name}: inserted {len(rows)} rows")


def main():
    args = _parse_args()

    sqlite_path = args.sqlite
    if not Path(sqlite_path).is_file():
        logger.error(f"SQLite database not found: {sqlite_path}")
        sys.exit(1)

    logger.info(f"SQLite: {sqlite_path}")
    logger.info(f"PostgreSQL: {args.postgres.split('@')[-1] if '@' in args.postgres else args.postgres}")

    # Step 1: Read SQLite data
    sqlite_engine = _connect_sqlite(sqlite_path)
    tables_data = _get_sqlite_data(sqlite_engine)

    if args.dry_run:
        total = sum(len(rows) for rows in tables_data.values())
        logger.info(f"DRY RUN: Would migrate {total} records from {len(tables_data)} tables.")
        logger.info("No changes made.")
        return

    # Step 2: Connect to PostgreSQL
    pg_engine = _connect_postgres(args.postgres)

    # Step 3: Create tables using SQLAlchemy models
    # We need to import the models to get the metadata
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from app.models.base import Base
    _create_tables(pg_engine, Base)

    # Step 4: Insert data
    _insert_data(pg_engine, tables_data)

    logger.info("Migration complete!")
    logger.info(f"Migrated {sum(len(rows) for rows in tables_data.values())} records to PostgreSQL.")


if __name__ == "__main__":
    main()
