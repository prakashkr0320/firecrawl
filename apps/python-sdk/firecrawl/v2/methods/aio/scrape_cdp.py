"""
Async CDP browser scraping functionality for Firecrawl v2 API.
"""

from typing import Optional, List, Literal, Dict, Any

from ...types import CdpScrapeResponse
from ...utils.error_handler import handle_response_error
from ...utils.http_client_async import AsyncHttpClient

CdpFormat = Literal["markdown", "html"]


async def scrape_cdp(
    client: AsyncHttpClient,
    cdp_url: str,
    target_id: str,
    *,
    selector: Optional[str] = None,
    allow_multiple_selectors: bool = False,
    timeout: Optional[int] = None,
    formats: Optional[List[CdpFormat]] = None,
    only_main_content: Optional[bool] = None,
) -> CdpScrapeResponse:
    if not cdp_url or not cdp_url.strip():
        raise ValueError("cdp_url cannot be empty")
    if not target_id or not target_id.strip():
        raise ValueError("target_id cannot be empty")

    payload: Dict[str, Any] = {
        "cdpUrl": cdp_url.strip(),
        "targetId": target_id.strip(),
    }

    if selector is not None:
        payload["selector"] = selector
    if allow_multiple_selectors:
        payload["allowMultipleSelectors"] = allow_multiple_selectors
    if timeout is not None:
        payload["timeout"] = timeout
    if formats is not None:
        payload["formats"] = formats
    if only_main_content is not None:
        payload["onlyMainContent"] = only_main_content

    http_timeout = (timeout / 1000) + 5 if timeout is not None else None

    response = await client.post(
        "/v2/cdp-browser-scrape",
        payload,
        timeout=http_timeout,
    )

    if response.status_code >= 400:
        handle_response_error(response, "scrape cdp")

    return CdpScrapeResponse.model_validate(response.json())
