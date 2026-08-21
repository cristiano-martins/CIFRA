"""
Verificação de certificado TLS. Conecta apenas ao IP já validado pelo
módulo ssrf_protection (o chamador é responsável por validar antes).
Nunca tenta contornar ou "quebrar" TLS — só lê o certificado apresentado.
"""
import socket
import ssl
from datetime import datetime, timezone

from app.config import settings

CERT_DATE_FMT = "%b %d %H:%M:%S %Y %Z"


def check_certificate(hostname: str, port: int = 443) -> dict:
    result = {
        "https_available": False,
        "cert_valid": False,
        "issuer": None,
        "subject": None,
        "not_before": None,
        "not_after": None,
        "days_until_expiry": None,
        "hostname_match": None,
        "error": None,
    }

    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    try:
        with socket.create_connection((hostname, port), timeout=settings.REQUEST_TIMEOUT_SECONDS) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert()
    except ssl.SSLCertVerificationError as exc:
        result["https_available"] = True
        result["cert_valid"] = False
        result["error"] = "Certificado inválido ou não confiável."
        result["hostname_match"] = "hostname mismatch" not in str(exc).lower()
        return result
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        result["error"] = f"Não foi possível estabelecer conexão HTTPS: {exc.__class__.__name__}"
        return result

    result["https_available"] = True
    result["cert_valid"] = True

    issuer = dict(x[0] for x in cert.get("issuer", []))
    subject = dict(x[0] for x in cert.get("subject", []))
    result["issuer"] = issuer.get("organizationName") or issuer.get("commonName")
    result["subject"] = subject.get("commonName")

    not_before = cert.get("notBefore")
    not_after = cert.get("notAfter")
    result["not_before"] = not_before
    result["not_after"] = not_after
    result["hostname_match"] = True  # já validado por context.check_hostname

    if not_after:
        try:
            expiry = datetime.strptime(not_after, CERT_DATE_FMT).replace(tzinfo=timezone.utc)
            days_left = (expiry - datetime.now(timezone.utc)).days
            result["days_until_expiry"] = days_left
            if days_left < 0:
                result["cert_valid"] = False
                result["error"] = "Certificado expirado."
        except ValueError:
            pass

    return result
