from contextlib import contextmanager
from collections.abc import Generator
from pathlib import Path

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.core.logging import get_logger
from app.db.base import Base

connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, connect_args=connect_args, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, class_=Session)
logger = get_logger(__name__)


def init_db() -> None:
    _maybe_recreate_sqlite_db()
    Base.metadata.create_all(bind=engine)
    _run_lightweight_migrations()
    settings.export_dir.mkdir(parents=True, exist_ok=True)


@contextmanager
def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _maybe_recreate_sqlite_db() -> None:
    if not settings.dev_recreate_db or not settings.database_url.startswith("sqlite:///"):
        return
    db_path = _sqlite_path_from_url(settings.database_url)
    if db_path and db_path.exists():
        db_path.unlink()
        logger.warning("sqlite_database_recreated", extra={"database_path": str(db_path)})


def _run_lightweight_migrations() -> None:
    if not engine.dialect.name == "sqlite":
        return
    inspector = inspect(engine)
    if "recommendations" in inspector.get_table_names():
        columns = {column["name"] for column in inspector.get_columns("recommendations")}
        if "metadata" not in columns:
            with engine.begin() as connection:
                connection.execute(text("ALTER TABLE recommendations ADD COLUMN metadata JSON"))
            logger.info("sqlite_migration_applied", extra={"table": "recommendations", "column": "metadata"})


def _sqlite_path_from_url(database_url: str) -> Path | None:
    prefix = "sqlite:///"
    if not database_url.startswith(prefix):
        return None
    raw_path = database_url[len(prefix) :]
    return Path(raw_path)
