import re
from urllib.parse import parse_qs, urlparse

from app.scanner import dns_scanner, reputation_scanner, tls_scanner
from app.scanner.risk_engine import RiskFlag, compute
from app.scanner.safe_fetch import safe_fetch
from app.security.ssrf_protection import UnsafeHostError, resolve_and_validate
from app.security.validation import normalize_url

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy",
}
SUSPICIOUS_TLDS = (
    ".zip", ".review", ".country", ".kim", ".cricket", ".science",
    ".work", ".party", ".gq", ".tk", ".ml", ".cf", ".top", ".click", ".link",
)
KNOWN_BRANDS = (
    "paypal", "google", "microsoft", "apple", "amazon", "netflix",
    "facebook", "instagram", "whatsapp", "bancodobrasil", "caixa",
    "itau", "santander", "bradesco", "nubank", "mercadolivre",
)
SECURITY_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "x-frame-options",
]


def _brand_lookalike(host: str) -> str | None:
    for brand in KNOWN_BRANDS:
        if brand in host and host != f"{brand}.com" and not host.endswith(f".{brand}.com"):
            return brand
    return None


def scan_url(raw_url: str) -> dict:
    url = normalize_url(raw_url)
    parsed = urlparse(url)
    host = parsed.hostname.lower()

    try:
        resolve_and_validate(host)
        host_blocked = False
    except UnsafeHostError:
        host_blocked = True

    fetch_result = None
    dns_records: dict[str, list[str]] = {}
    tls_info: dict = {}
    security_headers: dict[str, bool] = {}

    if not host_blocked:
        fetch_result = safe_fetch(url)
        dns_records = dns_scanner.lookup_all(host)
        if parsed.scheme == "https":
            tls_info = tls_scanner.check_certificate(host)
        if fetch_result and fetch_result.headers:
            security_headers = {h: (h in {k.lower() for k in fetch_result.headers}) for h in SECURITY_HEADERS}

    ip_as_host = bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}$", host))
    punycode = "xn--" in host
    has_at_symbol = "@" in url
    suspicious_tld = any(host.endswith(t) for t in SUSPICIOUS_TLDS)
    is_shortener = host in SHORTENERS
    brand = _brand_lookalike(host)
    https_used = parsed.scheme == "https"
    redirects_count = len(fetch_result.redirect_chain) - 1 if fetch_result and fetch_result.redirect_chain else 0

    reputation = {} if host_blocked else reputation_scanner.check_url_reputation(url)
    reputation_status = reputation_scanner.summarize(reputation) if reputation else "unknown"

    flags = [
        RiskFlag(host_blocked, 40, "O host resolve para um endereço interno/privado e foi bloqueado por segurança.", "Não é possível analisar destinos internos."),
        RiskFlag(not https_used, 15, "A URL não utiliza HTTPS.", "Evite inserir dados sensíveis em conexões sem HTTPS."),
        RiskFlag(ip_as_host, 20, "O host é um endereço IP em vez de um domínio nomeado.", "Desconfie de links que apontam diretamente para um IP."),
        RiskFlag(has_at_symbol, 25, 'A URL contém "@", técnica comum para mascarar o destino real.', 'Não acesse links com "@" sem confirmar o destino.'),
        RiskFlag(suspicious_tld, 12, "O domínio usa uma extensão (TLD) frequentemente associada a abuso.", "Confirme a legitimidade do domínio antes de prosseguir."),
        RiskFlag(punycode, 20, "O domínio usa codificação punycode.", "Compare visualmente com o domínio oficial esperado."),
        RiskFlag(bool(brand), 30, f'O domínio contém o termo "{brand}", associado a uma marca conhecida, sem corresponder ao domínio oficial.' if brand else "", "Não insira credenciais até confirmar que o domínio é realmente da marca."),
        RiskFlag(redirects_count >= 3, 10, "Quantidade elevada de redirecionamentos.", "Verifique cada salto do redirecionamento antes de confiar no destino final."),
        RiskFlag(bool(tls_info) and not tls_info.get("cert_valid", True) and tls_info.get("https_available"), 15, "O certificado TLS apresentado não é válido.", "Não prossiga sem verificar o certificado do site."),
        RiskFlag(reputation_status == "flagged", 30, "Uma ou mais fontes de reputação sinalizaram este recurso.", "Evite acessar este link até que os indicadores sejam esclarecidos."),
    ]

    risk = compute(flags)

    return {
        "target": url,
        "url_info": {
            "original_url": url,
            "final_url": fetch_result.final_url if fetch_result else None,
            "domain": host,
            "subdomain_count": max(0, host.count(".") - 1),
            "protocol": parsed.scheme.upper(),
            "port": parsed.port or (443 if parsed.scheme == "https" else 80),
            "path": parsed.path or "/",
            "params": sorted(parse_qs(parsed.query).keys()),
            "redirect_count": redirects_count,
            "redirect_chain": fetch_result.redirect_chain if fetch_result else [],
        },
        "network": {
            "dns": dns_records,
            "is_shortener": is_shortener,
        },
        "security": {
            "https_used": https_used,
            "tls": tls_info,
            "security_headers": security_headers,
        },
        "threat_intelligence": {
            "reputation": reputation,
            "reputation_status": reputation_status,
        },
        "fetch_error": fetch_result.error if fetch_result else "Host bloqueado por proteção SSRF.",
        "host_blocked": host_blocked,
        "risk": risk,
    }
