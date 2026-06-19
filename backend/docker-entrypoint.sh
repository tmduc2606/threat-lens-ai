#!/bin/bash
set -e

echo "=== ThreatLensAI Docker Entrypoint ==="

# If using PostgreSQL, wait for it to be ready
if [ -n "$DATABASE_URL" ] && echo "$DATABASE_URL" | grep -q "postgres"; then
    echo "Waiting for PostgreSQL..."
    until pg_isready -h "$(echo $DATABASE_URL | sed -n 's/.*@\(.*\):.*/\1/p')" -U postgres 2>/dev/null; do
        sleep 2
    done
    echo "PostgreSQL is ready."
fi

# Run schema migration if SQL files exist
if [ -d "/app/sql" ]; then
    echo "Running SQL schema..."
    for f in /app/sql/*.sql; do
        if [ -f "$f" ]; then
            if [ -n "$DATABASE_URL" ] && echo "$DATABASE_URL" | grep -q "postgres"; then
                PGPASSWORD=postgres psql -h "$(echo $DATABASE_URL | sed -n 's/.*@\(.*\):.*/\1/p')" -U postgres -d threatlensai -f "$f" 2>/dev/null || true
            else
                echo "SQLite: schema created by SQLAlchemy automatically."
            fi
        fi
    done
fi

# Import CSV data if database is empty
if [ -d "/app/data" ]; then
    echo "Checking if initial data needs to be loaded..."
    cd /app
    python -c "
import sys
from pathlib import Path
sys.path.insert(0, '/app')
from app.database import SessionLocal
from app.models.index import IntelIndex
db = SessionLocal()
count = db.query(IntelIndex).count()
db.close()
if count == 0:
    print('Database empty. Loading CSV data...')
    exec(open('load_csv.py').read())
else:
    print(f'Database has {count} records (skipping import).')
" || echo "Warning: CSV import skipped (may already be loaded)."
fi

echo "=== Starting ThreatLensAI API ==="
exec uvicorn backend.app.main:app --host 0.0.0.0 --port "${API_PORT:-8000}" --proxy-headers