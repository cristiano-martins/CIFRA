"""
Validação de entrada. Nada aqui faz rede — só formato.
Levanta ValueError com mensagens seguras para mostrar ao usuário.
"""
import re
from urllib.parse import urlparse, urlunparse

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

MAX_URL_LENGTH = 2048


def normalize_url(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("URL vazia.")
    if len(raw) > MAX_URL_LENGTH:
        raise ValueError("URL excede o tamanho máximo permitido.")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", raw):
        raw = "https://" + raw

    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Apenas URLs http/https são suportadas.")
    if not parsed.hostname:
        raise ValueError("URL inválida: nenhum host identificado.")

    # remove fragmento (#...) — não é enviado ao servidor de qualquer forma
    normalized = urlunparse(parsed._replace(fragment=""))
    return normalized


def normalize_domain(raw: str) -> str:
    raw = (raw or "").strip().lower()
    raw = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", "", raw)
    raw = raw.split("/")[0]
    raw = raw.split(":")[0]  # remove porta, se houver
    if not DOMAIN_RE.match(raw):
        raise ValueError("Domínio inválido. Use o formato exemplo.com.")
    return raw


def normalize_email(raw: str) -> str:
    raw = (raw or "").strip()
    if not EMAIL_RE.match(raw):
        raise ValueError("E-mail inválido. Use o formato usuario@dominio.com.")
    return raw


def split_email(email: str) -> tuple[str, str]:
    local, _, domain = email.partition("@")
    return local, domain.lower()
