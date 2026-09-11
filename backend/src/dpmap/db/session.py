"""Application metadata database sessions."""

import os
from functools import lru_cache
from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker


@lru_cache(maxsize=4)
def _session_factory(database_url: str) -> sessionmaker[Session]:
    return sessionmaker(create_engine(database_url, pool_pre_ping=True))


def get_session() -> Iterator[Session]:
    """Yield an app-DB session; the environment-held URL is never logged."""
    database_url = os.getenv("APP_DB_URL")
    if not database_url:
        raise RuntimeError("APP_DB_URL is required")
    with _session_factory(database_url)() as session:
        yield session
