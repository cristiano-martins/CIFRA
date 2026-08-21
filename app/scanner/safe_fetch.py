"""
Busca HTTP "SSRF-safe": nunca usa follow_redirects=True do httpx (que
seguiria redirecionamentos sem re-validar cada host). Em vez disso, segue
manualmente, validando CADA salto antes de conectar.
"""
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import httpx

from app.config import settings
from app.security.ssrf_protection import UnsafeHostError, resolve_and_validate

USER_AGENT = "CIPHER-Scanner/1.0 (+security-analysis-bot)"


@dataclass
class FetchResult:
    final_url: str
    redirect_chain: list[str] = field(default_factory=list)
    status_code: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    error: str | None = None
    blocked: bool = False


def safe_fetch(url: str, max_redirects: int | None = None) -> FetchResult:
    max_redirects = settings.MAX_REDIRECTS if max_redirects is None else max_redirects
    chain: list[str] = []
    current = url

    for _ in range(max_redirects + 1):
        parsed = urlparse(current)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return FetchResult(final_url=current, redirect_chain=chain, error="URL inválida durante o redirecionamento.")

        try:
            resolve_and_validate(parsed.hostname)
        except UnsafeHostError as exc:
            return FetchResult(final_url=current, redirect_chain=chain, blocked=True, error=str(exc))

        chain.append(current)

        try:
            with httpx.Client(
                timeout=settings.REQUEST_TIMEOUT_SECONDS,
                follow_redirects=False,
                headers={"User-Agent": USER_AGENT},
            ) as client:
                resp = client.get(current)
        except httpx.HTTPError as exc:
            return FetchResult(
                final_url=current,
                redirect_chain=chain,
                error=f"Falha de conexão: {exc.__class__.__name__}",
            )

        if resp.is_redirect:
            location = resp.headers.get("location")
            if not location:
                break
            current = urljoin(current, location)
            continue

        return FetchResult(
            final_url=current,
            redirect_chain=chain,
            status_code=resp.status_code,
            headers=dict(resp.headers),
        )

    return FetchResult(
        final_url=current,
        redirect_chain=chain,
        error="Número máximo de redirecionamentos excedido.",
    )
