import pytest
from unittest.mock import patch, MagicMock
import httpx


@patch("app.services.agent_client.httpx.Client")
def test_collect_via_agent_success(mock_client):
    from app.services.agent_client import collect_via_agent
    from app.core.config import settings
    
    with patch.object(settings, 'agent_endpoint', 'http://localhost:8000'):
        with patch.object(settings, 'agent_token', 'test-token'):
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"status": "ok"}
            
            mock_context = MagicMock()
            mock_context.__enter__ = MagicMock(return_value=mock_context)
            mock_context.__exit__ = MagicMock(return_value=None)
            mock_context.post = MagicMock(return_value=mock_response)
            mock_client.return_value = mock_context
            
            result = collect_via_agent("test-host")
            assert result == {"status": "ok"}