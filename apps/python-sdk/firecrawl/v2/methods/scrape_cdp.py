"""
CDP browser scraping functionality for Firecrawl v2 API.
"""

from typing import Optional, List, Literal, Dict, Any

from ..types import CdpScrapeResponse
from ..utils import HttpClient, handle_response_error

CdpFormat = Literal["markdown", "html"]


def scrape_cdp(
    client: HttpClient,
    cdp_url: str,
    target_id: str,
    *,
    selector: Optional[str] = None,
    allow_multiple_selectors: bool = False,
    timeout: Optional[int] = None,
    formats: Optional[List[CdpFormat]] = None,
    only_main_content: Optional[bool] = None,
) -> CdpScrapeResponse:
    """
    Scrape content from a client-owned CDP browser session.

    Args:
        client: HTTP client instance
        cdp_url: WebSocket URL of the remote CDP session
        target_id: CDP target to attach to
        selector: Optional CSS selector to scope extraction
        allow_multiple_selectors: Whether selector may match multiple elements
        timeout: Request timeout in milliseconds
        formats: Output formats to include (markdown and/or html)
        only_main_content: Whether to extract only main content

    Returns:
        CdpScrapeResponse with requested format fields and metadata
    """
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

    response = client.post("/v2/cdp-browser-scrape", payload, timeout=http_timeout)

    if not response.ok:
        handle_response_error(response, "scrape cdp")

    return CdpScrapeResponse.model_validate(response.json())
