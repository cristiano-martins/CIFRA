"""
Consultas DNS públicas via dnspython. Cada tipo de registro é consultado
separadamente — a ausência de um registro NÃO é tratada como indicador de
vulnerabilidade, apenas como "não encontrado".
"""
import dns.resolver

from app.config import settings

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]


def _resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.lifetime = settings.DNS_TIMEOUT_SECONDS
    r.timeout = settings.DNS_TIMEOUT_SECONDS
    return r


def query_record(domain: str, record_type: str) -> list[str]:
    try:
        answers = _resolver().resolve(domain, record_type)
        return sorted(str(rdata).rstrip(".") for rdata in answers)
    except dns.resolver.NXDOMAIN:
        return []
    except dns.resolver.NoAnswer:
        return []
    except dns.exception.Timeout:
        return []
    except Exception:
        return []


def lookup_all(domain: str) -> dict[str, list[str]]:
    return {rtype: query_record(domain, rtype) for rtype in RECORD_TYPES}


def domain_exists(domain: str) -> bool:
    """True se qualquer um dos tipos principais de registro existir."""
    for rtype in ("A", "AAAA", "MX", "NS"):
        if query_record(domain, rtype):
            return True
    return False


def get_txt_prefixed(domain: str, prefix: str) -> list[str]:
    """Retorna registros TXT que começam com um prefixo (ex.: 'v=spf1')."""
    txts = query_record(domain, "TXT")
    return [t.strip('"') for t in txts if t.strip('"').lower().startswith(prefix.lower())]


def get_spf(domain: str) -> list[str]:
    return get_txt_prefixed(domain, "v=spf1")


def get_dmarc(domain: str) -> list[str]:
    return get_txt_prefixed(f"_dmarc.{domain}", "v=dmarc1")
