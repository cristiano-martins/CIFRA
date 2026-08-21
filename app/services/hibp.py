"""
Integração opcional com Have I Been Pwned (breach intelligence) para o
módulo de Email Security. Requer HIBP_API_KEY (serviço pago) no ambiente.

IMPORTANTE: mesmo com a API configurada, esta função NUNCA deve retornar
senhas, tokens ou outros segredos vazados — apenas nomes/categorias das
violações em que o e-mail apareceu.
"""
import httpx

from app.config import settings

BASE_URL = "https://haveibeenpwned.com/api/v3/breachedaccount"


def check_email_exposure(email: str) -> dict:
    if not settings.HIBP_API_KEY:
        return {"status": "not_configured", "source": "Have I Been Pwned"}

    try:
        headers = {
            "hibp-api-key": settings.HIBP_API_KEY,
            "user-agent": "CIPHER-Scanner/1.0",
        }
        with httpx.Client(timeout=settings.REQUEST_TIMEOUT_SECONDS) as client:
            resp = client.get(
                f"{BASE_URL}/{email}",
                headers=headers,
                params={"truncateResponse": "true"},
            )
        if resp.status_code == 404:
            return {"status": "clean", "source": "Have I Been Pwned", "breaches": []}
        resp.raise_for_status()
        breaches = [item.get("Name") for item in resp.json()]
        return {"status": "exposed", "source": "Have I Been Pwned", "breaches": breaches}
    except httpx.HTTPError as exc:
        return {"status": "error", "source": "Have I Been Pwned", "error": exc.__class__.__name__}
