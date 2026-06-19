from __future__ import annotations

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

from .config import get_settings


def _build_async_url(database_url: str) -> str:
    if database_url.startswith("sqlite"):
        return database_url.replace("sqlite://", "sqlite+aiosqlite://")
    if database_url.startswith("postgresql://") or database_url.startswith("postgresql+psycopg2://"):
        return database_url.replace("postgresql+psycopg2://", "postgresql+asyncpg://").replace("postgresql://", "postgresql+asyncpg://")
    return database_url


settings = get_settings()
async_database_url = _build_async_url(settings.database_url)

engine_kwargs = {
    "echo": False,
    "future": True,
    "pool_pre_ping": True,
}

if async_database_url.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}
else:
    engine_kwargs["pool_recycle"] = 3600
    engine_kwargs["pool_size"] = 20
    engine_kwargs["max_overflow"] = 10

async_engine = create_async_engine(async_database_url, **engine_kwargs)

AsyncSessionLocal = async_sessionmaker(
    bind=async_engine,
    class_=AsyncSession,
    autocommit=False,
    autoflush=False,
    future=True,
)


async def get_async_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()
