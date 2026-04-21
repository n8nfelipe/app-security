import pytest
from unittest.mock import patch, MagicMock


@pytest.fixture(autouse=True)
def mock_init_db():
    with patch("app.db.session.init_db"):
        yield