from __future__ import annotations

import httpx

from app.core.config import settings
from app.core.errors import AgentModeUnavailableError, ScanExecutionError


def collect_via_agent(target_name: str | None = None) -> dict:
    if not settings.agent_endpoint:
        raise AgentModeUnavailableError("Agent mode requested but APPSEC_AGENT_ENDPOINT is not configured")

    headers = {}
    if settings.agent_token:
        headers["Authorization"] = f"Bearer {settings.agent_token}"

    try:
        with httpx.Client(timeout=15.0) as client:
            response = client.post(
                f"{settings.agent_endpoint.rstrip('/')}/api/v1/collect",
                json={"target_name": target_name},
                headers=headers,
            )
            response.raise_for_status()
            return response.json()
    except httpx.HTTPError as exc:
        raise ScanExecutionError(f"Agent mode failed safely: {exc}") from exc
