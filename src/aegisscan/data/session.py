"""DB 엔진 및 세션 (async)."""
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from .models import Base

# sync URL for create_all (SQLite)
SYNC_DATABASE_URL = "sqlite:///./aegisscan.db"


def get_engine(database_url: str):
    """비동기 엔진 생성. sqlite+aiosqlite 사용."""
    return create_async_engine(
        database_url,
        echo=False,
    )


def get_session_factory(engine):
    return async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )


async def get_session(database_url: str) -> AsyncGenerator[AsyncSession, None]:
    """세션 컨텍스트."""
    engine = get_engine(database_url)
    factory = get_session_factory(engine)
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db(database_url: str) -> None:
    """테이블 생성. SQLite는 동기 엔진으로 create_all 호출."""
    from sqlalchemy import create_engine
    sync_url = database_url.replace("+aiosqlite", "").replace("sqlite+aiosqlite", "sqlite")
    engine = create_engine(sync_url, echo=False)
    Base.metadata.create_all(engine)
    engine.dispose()
