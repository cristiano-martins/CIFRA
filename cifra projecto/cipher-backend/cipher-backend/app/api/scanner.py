import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.config import settings
from app.database import db
from app.scanner.domain_scanner import scan_domain
from app.scanner.email_scanner import scan_email
from app.scanner.url_scanner import scan_url
from app.security.rate_limit import rate_limiter

logger = logging.getLogger("cipher.scanner")

router = APIRouter(prefix="/api/scanner", tags=["scanner"])


class URLRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048)


class DomainRequest(BaseModel):
    domain: str = Field(..., min_length=1, max_length=253)


class EmailRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=254)


@router.post("/url", dependencies=[Depends(rate_limiter)])
def scan_url_endpoint(payload: URLRequest):
    try:
        result = scan_url(payload.url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception:
        logger.exception("Falha inesperada ao analisar URL")
        raise HTTPException(status_code=500, detail="Não foi possível concluir a análise. Tente novamente.")

    scan_id = db.save_scan("url", result["target"], result)
    return {"id": scan_id, **result}


@router.post("/domain", dependencies=[Depends(rate_limiter)])
def scan_domain_endpoint(payload: DomainRequest):
    try:
        result = scan_domain(payload.domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception:
        logger.exception("Falha inesperada ao analisar domínio")
        raise HTTPException(status_code=500, detail="Não foi possível concluir a análise. Tente novamente.")

    scan_id = db.save_scan("domain", result["target"], result)
    return {"id": scan_id, **result}


@router.post("/email", dependencies=[Depends(rate_limiter)])
def scan_email_endpoint(payload: EmailRequest):
    try:
        result = scan_email(payload.email)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception:
        logger.exception("Falha inesperada ao analisar e-mail")
        raise HTTPException(status_code=500, detail="Não foi possível concluir a análise. Tente novamente.")

    scan_id = db.save_scan("email", result["target"], result)
    return {"id": scan_id, **result}


@router.get("/history")
def get_history(limit: int = 30):
    limit = max(1, min(limit, 100))
    return db.get_history(limit=limit)


@router.get("/report/{scan_id}")
def get_report(scan_id: str):
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Análise não encontrada.")
    return scan


@router.delete("/history/{scan_id}")
def delete_history_item(scan_id: str):
    deleted = db.delete_scan(scan_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Análise não encontrada.")
    return {"deleted": True}


@router.delete("/history")
def clear_history():
    db.delete_all()
    return {"deleted": True}


@router.get("/status")
def engine_status():
    """
    Usado pelo dashboard do frontend para saber quais engines estão
    realmente configuradas (ex.: chaves de API presentes).
    """
    return {
        "dns": True,
        "tls": True,
        "whois": True,
        "virustotal": bool(settings.VIRUSTOTAL_API_KEY),
        "safe_browsing": bool(settings.GOOGLE_SAFE_BROWSING_API_KEY),
        "data_exposure": bool(settings.HIBP_API_KEY),
    }
