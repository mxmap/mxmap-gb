"""Lightweight GB pipeline based on local authority homepage CSV."""

from __future__ import annotations

import asyncio
import csv
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import httpx
from loguru import logger

from mail_municipalities.core.dns import lookup_a, lookup_mx
from mail_municipalities.domain_resolver.schemas import MunicipalityOutput, PipelineOutput
from mail_municipalities.domain_resolver.scraping import url_to_domain

_USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.10 Safari/605.1.1"
)


@dataclass(frozen=True, slots=True)
class GBMunicipality:
    code: str
    name: str
    region: str
    homepage_url: str
    domain: str | None
    tier_id: str

class RequestRateLimiter:
    """Simple global request limiter for async tasks."""

    def __init__(self, requests_per_second: float) -> None:
        if requests_per_second <= 0:
            raise ValueError("requests_per_second must be greater than zero")
        self._interval = 1.0 / requests_per_second
        self._next_allowed = 0.0
        self._lock = asyncio.Lock()

    async def wait_turn(self) -> None:
        async with self._lock:
            now = time.monotonic()
            sleep_for = self._next_allowed - now
            if sleep_for > 0:
                await asyncio.sleep(sleep_for)
                now = time.monotonic()
            self._next_allowed = now + self._interval


def load_local_authorities(csv_path: Path) -> list[GBMunicipality]:
    """Load GB local authorities from the semicolon-separated source CSV."""
    rows: list[GBMunicipality] = []
    with csv_path.open(encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f, delimiter=";")
        for row in reader:
            code = (row.get("gss") or "").strip()
            if not code:
                continue

            homepage_url = (row.get("homepage_url") or "").strip()
            domain = url_to_domain(homepage_url)
            if domain:
                domain = domain.lower()

            rows.append(
                GBMunicipality(
                    code=code,
                    name=(row.get("name") or "").strip(),
                    region=(row.get("country_name") or "").strip(),
                    tier_id= (row.get("tier_id") or "").strip(),
                    homepage_url=homepage_url,
                    domain=domain,
                )
            )
    return rows


async def _lookup_a_with_www_fallback(domain: str, limiter: RequestRateLimiter) -> str | None:
    await limiter.wait_turn()
    if await lookup_a(domain):
        return domain 
    await limiter.wait_turn()
    if await lookup_a(f"www.{domain}"): 
        return f"www.{domain}"
    return None


def _start_url(homepage_url: str, domain: str) -> str:
    if not homepage_url and domain:
        return f"https://{domain}"
    if "://" in homepage_url:
        return homepage_url
    return f"https://{domain}"


async def _resolve_final_domain(
    client: httpx.AsyncClient,
    start_url: str,
    limiter: RequestRateLimiter,
) -> str | None:
    await limiter.wait_turn()
    try:
        async with client.stream(
            "GET",
            start_url,
            follow_redirects=True,
            timeout=httpx.Timeout(15.0, connect=15.0),
        ) as response:
            if response.status_code >= 400:
                logger.debug("GB HTTP check failed for {} with status {}", start_url, response.status_code)
                return None
            final_domain = url_to_domain(str(response.url))
            return final_domain.lower() if final_domain else None
    except httpx.HTTPError as exc:
        logger.debug("GB HTTP check failed for {}: {}", start_url, exc)
        return None

# Prüfe ob für die Domain MX-REcords (ausnahme null MX-Records) hinterlegt sind
async def _has_mx_record(domain: str, limiter: RequestRateLimiter) -> bool:
    await limiter.wait_turn()
    mx_records = await lookup_mx(domain)
    return bool(mx_records) and mx_records != [""]


async def _resolve_one(
    municipality: GBMunicipality,
    client: httpx.AsyncClient,
    limiter: RequestRateLimiter,
) -> MunicipalityOutput:
    website = ""
    emails: list[str] = []

    if municipality.domain:
        if await lookup_a(municipality.domain):
            website = municipality.domain

        if not await _has_mx_record(municipality.domain, limiter):
            final_domain = await _resolve_final_domain(
                client,
                _start_url(municipality.homepage_url, municipality.domain),
                limiter,
            )
            if final_domain and final_domain != municipality.domain:
                website = final_domain
                if await _has_mx_record(final_domain, limiter):
                    logger.debug("GB MX records found at different location: {}", municipality.domain)
                    emails = [final_domain]

                else:
                    logger.debug("GB MX check failed for {}", final_domain)

            else:
                logger.debug("GB MX check failed for {}", final_domain)

        else:
            emails = [municipality.domain]
            logger.debug("GB MX records directly found for {}", municipality.domain)

            

    return MunicipalityOutput(
        code=municipality.code,
        name=municipality.name,
        region=municipality.region,
        website=website,
        emails=emails,
        tier_id = municipality.tier_id,
    )


async def run_pipeline_gb(
    *,
    csv_path: Path,
    output_dir: Path,
    dry_run: bool = False,
    requests_per_second: float = 3.0,
    concurrency: int = 5,
) -> None:
    """Run the lightweight GB pipeline and export domains_gb.json."""
    t0 = time.time()
    municipalities = load_local_authorities(csv_path)
    logger.info("GB: {} municipalities loaded from {}", len(municipalities), csv_path)

    if dry_run:
        with_domains = sum(1 for m in municipalities if m.domain)
        logger.info("=== DRY RUN -- GB ===")
        logger.info("Total municipalities: {}", len(municipalities))
        logger.info("With homepage domains: {}", with_domains)
        return

    limiter = RequestRateLimiter(requests_per_second=requests_per_second)
    sem = asyncio.Semaphore(concurrency)
    total = len(municipalities)
    done = 0
    results: list[MunicipalityOutput] = []

    async with httpx.AsyncClient(headers={"User-Agent": _USER_AGENT}, http2=True) as client:
        async def worker(municipality: GBMunicipality) -> MunicipalityOutput:
            async with sem:
                return await _resolve_one(municipality, client, limiter)

        tasks = [asyncio.create_task(worker(m)) for m in municipalities]
        for task in asyncio.as_completed(tasks):
            result = await task
            results.append(result)
            done += 1
            if done % 50 == 0 or done == total:
                logger.info("GB progress: {}/{}", done, total)

    results.sort(key=lambda m: m.code)
    output = PipelineOutput(
        generated=datetime.now(tz=timezone.utc),
        total=len(results),
        municipalities=results,
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "domains_gb.json"
    output_path.write_text(output.model_dump_json(indent=2), encoding="utf-8")

    with_emails = sum(1 for m in results if m.emails)
    logger.info("Wrote {}", output_path)
    logger.info(
        "GB summary: {} municipalities, {} with email domain ({:.1f}%)",
        len(results),
        with_emails,
        with_emails / max(len(results), 1) * 100.0,
    )
    logger.info("=== GB pipeline complete in {:.1f}s ===", time.time() - t0)
