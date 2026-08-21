"""
Integração com a API pública do VirusTotal (v3).
Requer VIRUSTOTAL_API_KEY no ambiente. Se ausente, retorna status
'not_configured' e o restante da análise continua normalmente.
"""
import base64

import httpx

from app.config import settings

BASE_URL = "https://www.virustotal.com/api/v3"


def _url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def check_url(url: str) -> dict:
    if not settings.VIRUSTOTAL_API_KEY:
        return {"status": "not_configured", "source": "VirusTotal"}

    try:
        headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
        with httpx.Client(timeout=settings.REQUEST_TIMEOUT_SECONDS) as client:
            resp = client.get(f"{BASE_URL}/urls/{_url_id(url)}", headers=headers)
        if resp.status_code == 404:
            return {"status": "unknown", "source": "VirusTotal", "note": "URL ainda não indexada."}
        resp.raise_for_status()
        data = resp.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        status = "flagged" if (malicious or suspicious) else "clean"
        return {
            "status": status,
            "source": "VirusTotal",
            "malicious_votes": malicious,
            "suspicious_votes": suspicious,
            "harmless_votes": stats.get("harmless", 0),
        }
    except httpx.HTTPError as exc:
        return {"status": "error", "source": "VirusTotal", "error": exc.__class__.__name__}


def check_domain(domain: str) -> dict:
    if not settings.VIRUSTOTAL_API_KEY:
        return {"status": "not_configured", "source": "VirusTotal"}

    try:
        headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
        with httpx.Client(timeout=settings.REQUEST_TIMEOUT_SECONDS) as client:
            resp = client.get(f"{BASE_URL}/domains/{domain}", headers=headers)
        if resp.status_code == 404:
            return {"status": "unknown", "source": "VirusTotal"}
        resp.raise_for_status()
        data = resp.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        status = "flagged" if (malicious or suspicious) else "clean"
        return {
            "status": status,
            "source": "VirusTotal",
            "malicious_votes": malicious,
            "suspicious_votes": suspicious,
        }
    except httpx.HTTPError as exc:
        return {"status": "error", "source": "VirusTotal", "error": exc.__class__.__name__}
