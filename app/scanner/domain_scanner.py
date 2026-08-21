from app.scanner import dns_scanner, reputation_scanner, tls_scanner
from app.scanner.risk_engine import RiskFlag, compute
from app.security.ssrf_protection import UnsafeHostError, resolve_and_validate
from app.security.validation import normalize_domain
from app.scanner.url_scanner import SUSPICIOUS_TLDS, _brand_lookalike


def _whois_lookup(domain: str) -> dict:
    """
    Best-effort. A biblioteca `python-whois` consulta servidores WHOIS
    públicos (porta 43) — cobertura varia por TLD e pode falhar/expirar.
    Nunca trate a ausência de dados como indicador de risco.
    """
    try:
        import whois  # python-whois — import tardio: dependência opcional
        data = whois.whois(domain)
        if not data or not data.get("domain_name"):
            return {"status": "not_available"}
        return {
            "status": "ok",
            "registrar": data.get("registrar"),
            "creation_date": str(data.get("creation_date")) if data.get("creation_date") else None,
            "expiration_date": str(data.get("expiration_date")) if data.get("expiration_date") else None,
            "name_servers": data.get("name_servers"),
        }
    except ImportError:
        return {"status": "not_configured", "note": "Instale 'python-whois' para habilitar esta verificação."}
    except Exception:
        return {"status": "not_available"}


def scan_domain(raw_domain: str) -> dict:
    domain = normalize_domain(raw_domain)

    try:
        resolve_and_validate(domain)
        blocked = False
    except UnsafeHostError:
        blocked = True

    dns_records = {} if blocked else dns_scanner.lookup_all(domain)
    tls_info = {} if blocked else tls_scanner.check_certificate(domain)
    whois_info = {} if blocked else _whois_lookup(domain)
    reputation = {} if blocked else reputation_scanner.check_domain_reputation(domain)
    reputation_status = reputation_scanner.summarize(reputation) if reputation else "unknown"

    num_hyphens = domain.count("-")
    suspicious_tld = any(domain.endswith(t) for t in SUSPICIOUS_TLDS)
    punycode = "xn--" in domain
    brand = _brand_lookalike(domain)
    dns_exists = any(dns_records.get(k) for k in ("A", "AAAA", "MX", "NS")) if dns_records else False

    flags = [
        RiskFlag(blocked, 40, "O domínio resolve para um endereço interno/privado e foi bloqueado por segurança.", "Não é possível analisar destinos internos."),
        RiskFlag(suspicious_tld, 12, "O domínio usa uma extensão (TLD) frequentemente associada a abuso.", "Confirme a legitimidade do domínio antes de confiar nele."),
        RiskFlag(punycode, 20, "O domínio usa codificação punycode.", "Compare visualmente com o domínio oficial esperado."),
        RiskFlag(num_hyphens >= 3, 10, "O domínio contém um número elevado de hífens.", "Domínios com muitos hífens são comuns em campanhas de phishing."),
        RiskFlag(bool(brand), 30, f'O domínio contém o termo "{brand}", associado a uma marca conhecida, sem corresponder ao domínio oficial.' if brand else "", "Não insira credenciais até confirmar a legitimidade do domínio."),
        RiskFlag(not blocked and not dns_exists, 15, "Nenhum registro DNS principal (A/AAAA/MX/NS) foi encontrado.", "Domínio pode estar inativo, mal configurado ou recém-criado."),
        RiskFlag(reputation_status == "flagged", 30, "Uma ou mais fontes de reputação sinalizaram este domínio.", "Trate este domínio com cautela até que os indicadores sejam esclarecidos."),
    ]

    risk = compute(flags)

    return {
        "target": domain,
        "domain_info": {
            "domain": domain,
            "dns": dns_records,
            "tls": tls_info,
            "whois": whois_info,
        },
        "threat_intelligence": {
            "reputation": reputation,
            "reputation_status": reputation_status,
        },
        "host_blocked": blocked,
        "risk": risk,
    }
