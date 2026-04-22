import pytest
from firecrawl.v2.methods.aio import browser as browser_module


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload
        self.status_code = 200

    def json(self):
        return self._payload


class _FakeClient:
    def __init__(self):
        self.last_post = None
        self.last_delete = None

    async def post(self, endpoint, payload):
        self.last_post = (endpoint, payload)
        return _FakeResponse(
            {
                "success": True,
                "id": "session-1",
                "cdpUrl": "ws://localhost:9222/devtools/browser/abc",
            }
        )

    async def delete(self, endpoint):
        self.last_delete = endpoint
        return _FakeResponse({"success": True})


@pytest.mark.asyncio
async def test_local_browser_calls_expected_endpoint():
    client = _FakeClient()
    resp = await browser_module.local_browser(
        client,
        ttl=120,
        activity_ttl=30,
        playwright={"viewport": {"width": 1280, "height": 720}},
    )
    assert client.last_post[0] == "/v2/local-browser"
    assert client.last_post[1]["ttl"] == 120
    assert client.last_post[1]["activityTtl"] == 30
    assert client.last_post[1]["playwright"]["viewport"]["height"] == 720
    assert resp.cdp_url == "ws://localhost:9222/devtools/browser/abc"


@pytest.mark.asyncio
async def test_delete_local_browser_calls_expected_endpoint():
    client = _FakeClient()
    resp = await browser_module.delete_local_browser(client, "session-1")
    assert client.last_delete == "/v2/local-browser/session-1"
    assert resp.success is True
