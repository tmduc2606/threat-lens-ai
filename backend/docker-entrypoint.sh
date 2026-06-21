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

# Create schema BEFORE CSV import check (which queries the tables).
# SQLAlchemy's create_all() is idempotent (IF NOT EXISTS).
echo "Creating database schema (if needed)..."
cd /app/backend
python -c "
import sys
sys.path.insert(0, '/app/backend')
from app.database import engine
from app.models.base import Base
import app.models as _models
Base.metadata.create_all(bind=engine)
print('Schema ready.')
"

# Import CSV data if database is empty
if [ -d "/app/data" ]; then
    echo "Checking if initial data needs to be loaded..."
    cd /app/backend
    PYTHONPATH=/app/backend python -c "
import sys
from app.database import SessionLocal
from app.models.index import IntelIndex
db = SessionLocal()
count = db.query(IntelIndex).count()
db.close()
if count == 0:
    print('Database empty. Loading CSV data...')
    import subprocess, os
    env = os.environ.copy()
    env['PYTHONPATH'] = '/app/backend'
    result = subprocess.run([sys.executable, '/app/load_csv.py'], capture_output=True, text=True, env=env)
    if result.returncode != 0:
        print(f'Warning: CSV import failed: {result.stderr}')
    else:
        print(result.stdout)
else:
    print(f'Database has {count} records (skipping import).')
" || echo "Warning: CSV import skipped (may already be loaded)."
fi

echo "=== Starting ThreatLensAI API ==="
exec uvicorn backend.app.main:app --host 0.0.0.0 --port "${API_PORT:-8000}" --proxy-headers
