import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path
import json
import tempfile


def test_load_rules():
    from app.services.scoring import load_rules
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump({"test": "data"}, f)
        f.flush()
        result = load_rules(Path(f.name))
        assert "test" in result


def test_load_rules_invalid():
    from app.services.scoring import load_rules
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        f.write("not valid json")
        f.flush()
        with pytest.raises(json.JSONDecodeError):
            load_rules(Path(f.name))