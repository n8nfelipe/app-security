from unittest.mock import MagicMock, patch
from pathlib import Path


def test_get_db():
    with patch("app.db.session.SessionLocal") as mock_session_class:
        mock_session = MagicMock()
        mock_session.__enter__ = MagicMock(return_value=mock_session)
        mock_session.__exit__ = MagicMock(return_value=False)
        mock_session_class.return_value = mock_session
        from app.db.session import get_db
        with get_db() as db:
            assert db is not None


def test_session_local():
    with patch("app.db.session.SessionLocal") as mock_session_class:
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        from app.db.session import SessionLocal
        session = SessionLocal()
        assert session is not None


def test_sqlite_path_from_url():
    from app.db.session import _sqlite_path_from_url

    result = _sqlite_path_from_url("sqlite:///./test.db")
    assert isinstance(result, Path)
    assert result.name == "test.db"

    result = _sqlite_path_from_url("postgresql://localhost/test")
    assert result is None