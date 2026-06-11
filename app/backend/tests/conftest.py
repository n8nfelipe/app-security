import os

import pytest
from unittest.mock import patch, MagicMock


@pytest.fixture(autouse=True)
def mock_init_db():
    with patch("app.db.session.init_db"), patch("app.db.session.engine"), patch("app.db.session.SessionLocal"):
        yield


def pytest_configure() -> None:
    os.environ.setdefault("APPSEC_API_TOKEN", "test-token")