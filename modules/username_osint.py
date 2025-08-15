import asyncio
import json
import random
from pathlib import Path
from typing import Dict, List

import aiohttp
from aiohttp import ClientResponse
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TimeElapsedColumn

console = Console()

SITES_PATH = Path(__file__).resolve().parent.parent / "data" / "sites.json"

DEFAULT_HEADERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.2 Mobile/15E148 Safari/604.1",
]


class UsernameScanner:
    def __init__(self, timeout: int = 15, concurrency: int = 50, retries: int = 2, proxy: str | None = None):
        self.timeout = timeout
        self.concurrency = concurrency
        self.retries = retries
        self.proxy = proxy
        with open(SITES_PATH, "r", encoding="utf-8") as f:
            self.sites: Dict[str, dict] = json.load(f)

    def scan(self, username: str) -> dict:
        results = asyncio.run(self._scan_async(username))
        return {"accounts": results, "summary": {"matches": len(results)}}

    async def _scan_async(self, username: str) -> List[dict]:
        sem = asyncio.Semaphore(self.concurrency)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            tasks = []
            for site, cfg in self.sites.items():
                tasks.append(self._probe_site(sem, session, site, cfg, username))
            results = []
            with Progress(SpinnerColumn(), *Progress.get_default_columns(), TimeElapsedColumn(), transient=True) as p:
                task_id = p.add_task("Scanning social sites", total=len(tasks))
                for coro in asyncio.as_completed(tasks):
                    res = await coro
                    if res:
                        console.print(f"[green][FOUND][/green] {res['site']}: {res['url']}")
                        results.append(res)
                    p.advance(task_id)
        return results

    async def _probe_site(self, sem, session: aiohttp.ClientSession, site: str, cfg: dict, username: str):
        url = cfg.get("url", "").replace("{account}", username)
        error_type = cfg.get("errorType", "status_code")
        error_msg = cfg.get("errorMsg")
        request_head_only = cfg.get("request_head_only", False)
        headers = {"User-Agent": random.choice(DEFAULT_HEADERS)}
        if cfg.get("headers"):
            headers.update(cfg["headers"])  # allow site-specific headers

        for attempt in range(self.retries + 1):
            try:
                async with sem:
                    method = session.head if request_head_only else session.get
                    async with method(url, proxy=self.proxy, headers=headers, allow_redirects=True) as resp:
                        if await self._is_hit(resp, error_type, error_msg):
                            return {"site": site, "url": str(resp.url), "status": "FOUND"}
                        else:
                            return None
            except asyncio.TimeoutError:
                if attempt >= self.retries:
                    return None
            except aiohttp.ClientError:
                if attempt >= self.retries:
                    return None
        return None

    async def _is_hit(self, resp: ClientResponse, error_type: str, error_msg: str | None) -> bool:
        # Sherlock-style detection rules with enhancements
        status = resp.status
        text = None
        if error_type in {"message", "regex"}:
            # read text only when necessary to save time
            text = await resp.text(errors="ignore")

        if error_type == "status_code":
            return status == 200
        if error_type == "message":
            # if error message NOT present, assume account exists
            return error_msg and (error_msg not in (text or ""))
        if error_type == "response_url":
            return str(resp.url) == str(resp.request_info.url)
        if error_type == "regex":
            import re
            if not error_msg:
                return status == 200
            return re.search(error_msg, text or "", re.I) is not None
        # fallback
        return status == 200
