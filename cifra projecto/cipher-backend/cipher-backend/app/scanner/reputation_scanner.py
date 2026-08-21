from app.services import safe_browsing, virustotal


def check_url_reputation(url: str) -> dict:
    return {
        "virustotal": virustotal.check_url(url),
        "safe_browsing": safe_browsing.check_url(url),
    }


def check_domain_reputation(domain: str) -> dict:
    return {
        "virustotal": virustotal.check_domain(domain),
    }


def summarize(reputation: dict) -> str:
    """
    'clean' | 'flagged' | 'unknown' — usado pelo risk_engine.
    'unknown' cobre tanto 'not_configured' quanto 'error' quanto 'unknown':
    a ausência de confirmação nunca deve virar uma alegação de segurança.
    """
    statuses = [source.get("status") for source in reputation.values()]
    if "flagged" in statuses:
        return "flagged"
    if all(s in ("not_configured", "error", "unknown") for s in statuses):
        return "unknown"
    return "clean"
