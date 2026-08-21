import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.scanner import router as scanner_router
from app.config import settings
from app.database.db import init_db

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cipher")

app = FastAPI(
    title="CIPHER Scanner API",
    description="Análise defensiva de URLs, domínios e e-mails a partir de fontes públicas e legítimas.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type"],
)

app.include_router(scanner_router)


@app.on_event("startup")
def on_startup():
    init_db()
    logger.info("CIPHER Scanner API iniciado.")


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # Nunca expõe stack traces ou detalhes internos ao cliente.
    logger.exception("Erro não tratado em %s", request.url.path)
    return JSONResponse(
        status_code=500,
        content={"detail": "Erro interno. A equipe já foi notificada pelos logs do servidor."},
    )


@app.get("/")
def root():
    return {"service": "CIPHER Scanner API", "status": "online"}
