"""
Proteção contra SSRF (Server-Side Request Forgery).

Regra geral: NUNCA conectar a um host antes de resolver seu(s) IP(s) e
confirmar que nenhum deles aponta para rede interna, loopback, link-local,
multicast, reservada ou para endpoints de metadata de nuvem.

Limitação conhecida (DNS rebinding): a validação abaixo resolve o host e
checa os IPs imediatamente antes de cada requisição, o que cobre a grande
maioria dos ataques de SSRF "simples". Um atacante sofisticado pode tentar
trocar a resposta DNS entre a validação e a conexão real (rebinding). Uma
mitigação completa exige "pinar" a conexão TCP no IP validado no nível de
transporte. Isso NÃO está implementado aqui por simplicidade — se este
scanner for exposto publicamente, recomenda-se adicionar:
  (a) um proxy de egress que resolve e conecta de forma atômica, ou
  (b) regras de firewall de saída permitindo apenas portas 80/443 para
      faixas de IP público, ou
  (c) uma biblioteca de HTTP client com suporte a IP pinning.
"""
import ipaddress
import socket

BLOCKED_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",
    "metadata.internal",
}
BLOCKED_HOSTNAME_SUFFIXES = (".local", ".internal", ".localhost")

# Endpoints de metadata conhecidos de provedores de nuvem (AWS/GCP/Azure/etc.)
BLOCKED_IPS = {
    "169.254.169.254",  # AWS / GCP / Azure metadata
    "169.254.170.2",    # ECS task metadata
    "::1",
}


class UnsafeHostError(ValueError):
    """Levantado quando um host resolve para um destino não permitido."""


def _is_ip_blocked(ip_str: str) -> bool:
    if ip_str in BLOCKED_IPS:
        return True
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # não conseguiu parsear -> trata como não seguro
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def resolve_and_validate(hostname: str) -> list[str]:
    """
    Resolve um hostname e garante que NENHUM IP resultante seja interno.
    Retorna a lista de IPs válidos (para uso informativo) ou levanta
    UnsafeHostError / socket.gaierror.
    """
    hostname_lower = hostname.lower().rstrip(".")

    if hostname_lower in BLOCKED_HOSTNAMES:
        raise UnsafeHostError(f"Host bloqueado por política: {hostname}")
    if any(hostname_lower.endswith(suf) for suf in BLOCKED_HOSTNAME_SUFFIXES):
        raise UnsafeHostError(f"Host bloqueado por política: {hostname}")

    try:
        infos = socket.getaddrinfo(hostname_lower, None)
    except socket.gaierror as exc:
        raise UnsafeHostError(f"Não foi possível resolver o host: {hostname}") from exc

    ips = sorted({info[4][0] for info in infos})
    if not ips:
        raise UnsafeHostError(f"Host não resolveu para nenhum IP: {hostname}")

    for ip_str in ips:
        if _is_ip_blocked(ip_str):
            raise UnsafeHostError(
                f"Host resolve para um IP não permitido ({ip_str}). "
                "Endereços internos, privados ou de metadata não são analisados."
            )

    return ips


def is_safe_host(hostname: str) -> bool:
    try:
        resolve_and_validate(hostname)
        return True
    except UnsafeHostError:
        return False
