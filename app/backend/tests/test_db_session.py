from app.db.session import get_db, SessionLocal


def test_get_db():
    with get_db() as db:
        assert db is not None


def test_session_local():
    session = SessionLocal()
    assert session is not None
    session.close()


def test_sqlite_path_from_url():
    from app.db.session import _sqlite_path_from_url
    from pathlib import Path
    
    result = _sqlite_path_from_url("sqlite:///./test.db")
    assert isinstance(result, Path)
    assert result.name == "test.db"
    
    result = _sqlite_path_from_url("postgresql://localhost/test")
    assert result is None