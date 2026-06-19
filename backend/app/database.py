from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from .config import get_settings

settings = get_settings()

connect_args = {}
engine_kwargs = {
    "echo": False,
    "future": True,
    "pool_pre_ping": True,
}

if settings.database_url.startswith("sqlite"):
    connect_args = {"check_same_thread": False}
    engine_kwargs["connect_args"] = connect_args
else:
    engine_kwargs["pool_recycle"] = 3600

engine = create_engine(settings.database_url, **engine_kwargs)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    future=True,
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()