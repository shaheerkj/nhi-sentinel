"""Identity API tests — suspension lifecycle.

Verifies the endpoints called by the anomaly service when an anomaly
threshold or burst is detected. Uses fakeredis to avoid requiring
a live Redis instance.
"""

from __future__ import annotations

from unittest.mock import patch

import fakeredis
import pytest
from fastapi.testclient import TestClient

from identity.api import app


@pytest.fixture
def fake_redis_patched():
    fake = fakeredis.FakeRedis(decode_responses=True)
    with patch("identity.api._get_redis", return_value=fake):
        yield fake


@pytest.fixture
def client(fake_redis_patched):
    return TestClient(app)


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["service"] == "nhi-identity"


def test_suspend_creates_redis_entry(client, fake_redis_patched):
    resp = client.post(
        "/identities/agent-data-001/suspend",
        json={"reason": "Anomaly score 0.97 > 0.95"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["agent_id"] == "agent-data-001"
    assert body["status"] == "SUSPENDED"
    assert body["newly_suspended"] is True
    # Confirm it's actually in the same Redis set the PEP will check
    assert fake_redis_patched.sismember("identities:suspended", "agent-data-001")


def test_suspend_is_idempotent(client):
    client.post("/identities/agent-data-001/suspend", json={"reason": "first"})
    resp = client.post("/identities/agent-data-001/suspend", json={"reason": "second"})
    assert resp.status_code == 200
    assert resp.json()["newly_suspended"] is False


def test_unsuspend_removes_entry(client, fake_redis_patched):
    client.post("/identities/agent-data-001/suspend", json={"reason": "test"})
    resp = client.post("/identities/agent-data-001/unsuspend")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ACTIVE"
    assert not fake_redis_patched.sismember("identities:suspended", "agent-data-001")


def test_unsuspend_unknown_returns_404(client):
    resp = client.post("/identities/never-suspended/unsuspend")
    assert resp.status_code == 404


def test_status_for_active_identity(client):
    resp = client.get("/identities/agent-fresh-001/status")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ACTIVE"


def test_status_for_suspended_identity_includes_reason(client):
    client.post(
        "/identities/agent-data-001/suspend",
        json={"reason": "Burst: 50 deletes in 10s"},
    )
    resp = client.get("/identities/agent-data-001/status")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "SUSPENDED"
    assert "Burst" in body["reason"]


def test_list_suspended(client):
    client.post("/identities/agent-1/suspend", json={"reason": "a"})
    client.post("/identities/agent-2/suspend", json={"reason": "b"})
    resp = client.get("/identities/suspended")
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 2
    assert set(body["agents"]) == {"agent-1", "agent-2"}


def test_metrics_endpoint(client):
    client.post("/identities/agent-1/suspend", json={"reason": "test"})
    resp = client.get("/metrics")
    assert resp.status_code == 200
    body = resp.text
    assert "nhi_suspensions_total" in body
    assert "nhi_identities_suspended_current 1" in body
