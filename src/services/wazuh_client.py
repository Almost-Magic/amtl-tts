"""Client for communicating with the Wazuh SIEM API."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import httpx


class WazuhClientError(Exception):
    """Raised when Wazuh API communication fails."""


class WazuhClient:
    """HTTP client for the Wazuh REST API."""

    def __init__(
        self,
        api_url: str,
        api_user: str,
        api_password: str,
        verify_ssl: bool = True,
    ) -> None:
        self.api_url = api_url.rstrip("/")
        self.api_user = api_user
        self.api_password = api_password
        self.verify_ssl = verify_ssl
        self._token: str | None = None
        self._token_expiry: datetime | None = None

    async def _authenticate(self) -> str:
        """Authenticate with the Wazuh API and return a JWT token."""
        async with httpx.AsyncClient(verify=self.verify_ssl) as client:
            response = await client.post(
                f"{self.api_url}/security/user/authenticate",
                auth=(self.api_user, self.api_password),
            )
            if response.status_code != 200:
                raise WazuhClientError(
                    f"Authentication failed: {response.status_code} {response.text}"
                )
            data = response.json()
            self._token = data.get("data", {}).get("token", "")
            self._token_expiry = datetime.now(timezone.utc)
            return self._token

    async def _get_headers(self) -> dict[str, str]:
        """Return auth headers, refreshing token if needed."""
        if not self._token:
            await self._authenticate()
        return {"Authorization": f"Bearer {self._token}"}

    async def get_alerts(
        self,
        limit: int = 100,
        offset: int = 0,
        level_min: int = 0,
        time_range_hours: int = 24,
    ) -> list[dict[str, Any]]:
        """Fetch recent alerts from Wazuh."""
        headers = await self._get_headers()
        async with httpx.AsyncClient(verify=self.verify_ssl) as client:
            response = await client.get(
                f"{self.api_url}/alerts",
                headers=headers,
                params={
                    "limit": limit,
                    "offset": offset,
                    "level": f"{level_min}-15",
                },
            )
            if response.status_code != 200:
                raise WazuhClientError(
                    f"Failed to fetch alerts: {response.status_code} {response.text}"
                )
            data = response.json()
            return data.get("data", {}).get("affected_items", [])

    async def get_agents(self) -> list[dict[str, Any]]:
        """Fetch registered agents."""
        headers = await self._get_headers()
        async with httpx.AsyncClient(verify=self.verify_ssl) as client:
            response = await client.get(
                f"{self.api_url}/agents",
                headers=headers,
            )
            if response.status_code != 200:
                raise WazuhClientError(
                    f"Failed to fetch agents: {response.status_code} {response.text}"
                )
            data = response.json()
            return data.get("data", {}).get("affected_items", [])

    async def test_connection(self) -> bool:
        """Test if the Wazuh connection is working."""
        try:
            await self._authenticate()
            return True
        except (WazuhClientError, httpx.HTTPError):
            return False
