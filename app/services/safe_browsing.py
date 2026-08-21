"""
Integração com a API Google Safe Browsing v4 (threatMatches.find).
Requer GOOGLE_SAFE_BROWSING_API_KEY no ambiente.
"""
import httpx

from app.config import settings

BASE_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]


def check_url(url: str) -> dict:
    if not settings.GOOGLE_SAFE_BROWSING_API_KEY:
        return {"status": "not_configured", "source": "Google Safe Browsing"}

    body = {
        "client": {"clientId": "cipher-scanner", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": THREAT_TYPES,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        with httpx.Client(timeout=settings.REQUEST_TIMEOUT_SECONDS) as client:
            resp = client.post(
                BASE_URL,
                params={"key": settings.GOOGLE_SAFE_BROWSING_API_KEY},
                json=body,
            )
        resp.raise_for_status()
        data = resp.json()
        matches = data.get("matches", [])
        return {
            "status": "flagged" if matches else "clean",
            "source": "Google Safe Browsing",
            "threat_types": sorted({m.get("threatType") for m in matches}) if matches else [],
        }
    except httpx.HTTPError as exc:
        return {"status": "error", "source": "Google Safe Browsing", "error": exc.__class__.__name__}
