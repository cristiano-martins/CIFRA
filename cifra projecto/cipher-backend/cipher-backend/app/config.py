"""
Configurações centrais do CIPHER Scanner.

Todas as chaves de API e segredos vêm de variáveis de ambiente — nunca
ficam hard-coded aqui nem são expostas ao frontend. Veja .env.example.
"""
import os
from dotenv import load_dotenv

load_dotenv()


def _env_list(name: str, default: str) -> list[str]:
    raw = os.getenv(name, default)
    return [item.strip() for item in raw.split(",") if item.strip()]


class Settings:
    # --- Fontes de threat intelligence (opcionais) ---
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    GOOGLE_SAFE_BROWSING_API_KEY: str = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
    HIBP_API_KEY: str = os.getenv("HIBP_API_KEY", "")  # Have I Been Pwned (data exposure)

    # --- Rede / segurança ---
    REQUEST_TIMEOUT_SECONDS: float = float(os.getenv("REQUEST_TIMEOUT_SECONDS", "6"))
    DNS_TIMEOUT_SECONDS: float = float(os.getenv("DNS_TIMEOUT_SECONDS", "4"))
    MAX_REDIRECTS: int = int(os.getenv("MAX_REDIRECTS", "5"))
    MAX_RESPONSE_BYTES: int = int(os.getenv("MAX_RESPONSE_BYTES", str(2 * 1024 * 1024)))  # 2 MB

    # --- Rate limiting ---
    RATE_LIMIT_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "20"))

    # --- CORS ---
    # Em produção, restrinja a(s) origem(ns) real(is) do frontend.
    CORS_ORIGINS: list[str] = _env_list("CORS_ORIGINS", "http://localhost:5500,http://127.0.0.1:5500")

    # --- Banco de dados ---
    DATABASE_PATH: str = os.getenv("DATABASE_PATH", "cipher.db")


settings = Settings()
