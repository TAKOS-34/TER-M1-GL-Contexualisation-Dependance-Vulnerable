"""HTTP utilities."""
import asyncio
from typing import TypeVar, Callable, Any, Optional
import httpx
from core.logger import get_logger
from core.exceptions import SourceTimeoutError, SourceConnectionError
from core.config import settings

logger = get_logger(__name__)

T = TypeVar("T")


async def with_retry(
    func: Callable[..., Any],
    source: str,
    max_retries: int = 3,
    backoff: float = 0.5,
    *args,
    **kwargs
) -> Any:
    """Execute function with exponential backoff retry logic."""
    for attempt in range(max_retries):
        try:
            return await func(*args, **kwargs)
        except asyncio.TimeoutError:
            if attempt == max_retries - 1:
                raise SourceTimeoutError(source, settings.sources.timeout)
            wait_time = backoff * (2 ** attempt)
            logger.warning(
                f"[{source}] Timeout (attempt {attempt + 1}/{max_retries}), "
                f"retrying in {wait_time}s..."
            )
            await asyncio.sleep(wait_time)
        except (httpx.ConnectError, httpx.NetworkError) as e:
            if attempt == max_retries - 1:
                raise SourceConnectionError(source, str(e))
            wait_time = backoff * (2 ** attempt)
            logger.warning(
                f"[{source}] Connection error (attempt {attempt + 1}/{max_retries}), "
                f"retrying in {wait_time}s...: {e}"
            )
            await asyncio.sleep(wait_time)
        except Exception as e:
            logger.error(f"[{source}] Unexpected error: {e}")
            raise


async def make_http_request(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    source: str,
    **kwargs
) -> httpx.Response:
    """Make HTTP request with error handling."""
    logger.debug(f"[{source}] {method} {url}")
    resp = await client.request(method, url, **kwargs)
    resp.raise_for_status()
    return resp
