#!/bin/bash
set -e

echo "=== ThreatLensAI Docker Entrypoint ==="

# If using PostgreSQL, wait for it to be ready
if [ -n "$DATABASE_URL" ] && echo "$DATABASE_URL" | grep -q "postgres"; then
    echo "Waiting for PostgreSQL..."
    python -c "
import os, time, re, sys
url = os.environ.get('DATABASE_URL', '')
m = re.search(r'@([^:]+):', url)
host = m.group(1) if m else 'db'
print(f'  host={host}', flush=True)
while True:
    import psycopg2
    try:
        conn = psycopg2.connect(host=host, port=5432, user='postgres', password='postgres', dbname='threatlensai', connect_timeout=3)
        conn.close()
        print('  PostgreSQL is ready.', flush=True)
        break
    except Exception as e:
        print(f'  Waiting... ({e})', flush=True)
        time.sleep(2)
    except KeyboardInterrupt:
        sys.exit(1)
"
fi

# Schema is managed by SQLAlchemy's Base.metadata.create_all() in main.py:on_startup()
# SQL files in /app/sql/ are reference/documentation only.
echo "Schema will be created by SQLAlchemy on startup."

# Import CSV data if database is empty
if [ -d "/app/data" ]; then
    echo "Checking if initial data needs to be loaded..."
    cd /app
    python -c "
import sys
from pathlib import Path
sys.path.insert(0, '/app/backend')
from app.database import SessionLocal
from app.models.index import IntelIndex
db = SessionLocal()
count = db.query(IntelIndex).count()
db.close()
if count == 0:
    print('Database empty. Loading CSV data...')
    load_script = Path('/app/load_csv.py')
    if load_script.exists():
        exec(load_script.read_text())
    else:
        print('Warning: load_csv.py not found.')
else:
    print(f'Database has {count} records (skipping import).')
" || echo "Warning: CSV import skipped (may already be loaded)."
fi

echo "=== Starting ThreatLensAI API ==="
exec uvicorn backend.app.main:app --host 0.0.0.0 --port "${API_PORT:-8000}" --proxy-headers