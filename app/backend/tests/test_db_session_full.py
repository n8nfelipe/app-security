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


def test_init_db():
    from unittest.mock import MagicMock, patch

    with patch("app.db.session.settings") as mock_settings:
        mock_settings.dev_recreate_db = False
        mock_settings.database_url = "sqlite:///./test.db"
        mock_settings.export_dir = MagicMock()
        mock_settings.export_dir.mkdir = MagicMock()

        with patch("app.db.session._maybe_recreate_sqlite_db"), \
             patch("app.db.session.Base.metadata.create_all"), \
             patch("app.db.session._run_lightweight_migrations"):
            from app.db.session import init_db
            init_db()


def test_maybe_recreate_sqlite_db_disabled():
    from unittest.mock import patch

    with patch("app.db.session.settings") as mock_settings:
        mock_settings.dev_recreate_db = False
        mock_settings.database_url = "sqlite:///./test.db"

        from app.db.session import _maybe_recreate_sqlite_db
        _maybe_recreate_sqlite_db()


def test_maybe_recreate_sqlite_db_not_sqlite():
    from unittest.mock import patch

    with patch("app.db.session.settings") as mock_settings:
        mock_settings.dev_recreate_db = True
        mock_settings.database_url = "postgresql://localhost/test"

        from app.db.session import _maybe_recreate_sqlite_db
        _maybe_recreate_sqlite_db()


def test_maybe_recreate_sqlite_db_file_not_exists():
    from unittest.mock import patch, MagicMock

    with patch("app.db.session.settings") as mock_settings:
        mock_settings.dev_recreate_db = True
        mock_settings.database_url = "sqlite:///./nonexistent.db"

        with patch("app.db.session._sqlite_path_from_url", return_value=None):
            from app.db.session import _maybe_recreate_sqlite_db
            _maybe_recreate_sqlite_db()


def test_run_lightweight_migrations_not_sqlite():
    from unittest.mock import patch

    with patch("app.db.session.engine") as mock_engine:
        mock_engine.dialect.name = "postgresql"

        from app.db.session import _run_lightweight_migrations
        _run_lightweight_migrations()


def test_run_lightweight_migrations_no_recommendations_table():
    from unittest.mock import patch, MagicMock

    mock_inspector = MagicMock()
    mock_inspector.get_table_names.return_value = []

    with patch("app.db.session.engine") as mock_engine:
        mock_engine.dialect.name = "sqlite"
        with patch("app.db.session.inspect", return_value=mock_inspector):
            from app.db.session import _run_lightweight_migrations
            _run_lightweight_migrations()


def test_run_lightweight_migrations_column_exists():
    from unittest.mock import patch, MagicMock

    mock_inspector = MagicMock()
    mock_inspector.get_table_names.return_value = ["recommendations"]
    mock_inspector.get_columns.return_value = [{"name": "metadata"}]

    with patch("app.db.session.engine") as mock_engine:
        mock_engine.dialect.name = "sqlite"
        with patch("app.db.session.inspect", return_value=mock_inspector):
            from app.db.session import _run_lightweight_migrations
            _run_lightweight_migrations()


def test_run_lightweight_migrations_add_column():
    from unittest.mock import patch, MagicMock

    mock_inspector = MagicMock()
    mock_inspector.get_table_names.return_value = ["recommendations"]
    mock_inspector.get_columns.return_value = [{"name": "id"}]

    mock_connection = MagicMock()

    with patch("app.db.session.engine") as mock_engine:
        mock_engine.dialect.name = "sqlite"
        with patch("app.db.session.inspect", return_value=mock_inspector):
            mock_engine.begin.return_value.__enter__ = MagicMock(return_value=mock_connection)
            mock_engine.begin.return_value.__exit__ = MagicMock(return_value=None)
            from app.db.session import _run_lightweight_migrations
            _run_lightweight_migrations()


def test_sqlite_path_from_url_with_path():
    from app.db.session import _sqlite_path_from_url

    result = _sqlite_path_from_url("sqlite:///./subdir/test.db")
    assert result.name == "test.db"


def test_sqlite_path_from_url_postgresql():
    from app.db.session import _sqlite_path_from_url

    result = _sqlite_path_from_url("sqlite+pysqlite:///./test.db")
    assert result is None


def test_sqlite_path_from_url_invalid_prefix():
    from app.db.session import _sqlite_path_from_url

    result = _sqlite_path_from_url("mysql://localhost/test")
    assert result is None