"""
Rate limiting simples, em memória, por IP do cliente.

Adequado para um único processo/worker. Se o backend for rodar com múltiplos
workers (ex.: `uvicorn --workers 4`) ou em múltiplas instâncias, este limite
NÃO é compartilhado entre processos — troque por um backend compartilhado
(Redis, por exemplo) antes de escalar horizontalmente.
"""
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request

from app.config import settings

_WINDOW_SECONDS = 60
_hits: dict[str, deque] = defaultdict(deque)


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def rate_limiter(request: Request) -> None:
    ip = _client_ip(request)
    now = time.monotonic()
    window = _hits[ip]

    while window and now - window[0] > _WINDOW_SECONDS:
        window.popleft()

    if len(window) >= settings.RATE_LIMIT_PER_MINUTE:
        raise HTTPException(
            status_code=429,
            detail="Limite de requisições excedido. Tente novamente em instantes.",
        )

    window.append(now)
