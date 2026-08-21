from app.scanner import dns_scanner
from app.scanner.risk_engine import RiskFlag, compute
from app.security.validation import normalize_email, split_email
from app.services import hibp

DISPOSABLE_DOMAINS = {
    "mailinator.com", "10minutemail.com", "guerrillamail.com",
    "tempmail.com", "yopmail.com", "trashmail.com", "getnada.com",
}
FREE_WEBMAILS = {
    "gmail.com", "yahoo.com", "yahoo.com.br", "hotmail.com",
    "outlook.com", "icloud.com", "live.com", "bol.com.br",
}


def scan_email(raw_email: str) -> dict:
    email = normalize_email(raw_email)
    _local, domain = split_email(email)

    domain_exists = dns_scanner.domain_exists(domain)
    mx_records = dns_scanner.query_record(domain, "MX")
    spf_records = dns_scanner.get_spf(domain)
    dmarc_records = dns_scanner.get_dmarc(domain)
    is_disposable = domain in DISPOSABLE_DOMAINS
    is_free_webmail = domain in FREE_WEBMAILS

    exposure = hibp.check_email_exposure(email)

    flags = [
        RiskFlag(not domain_exists, 30, "O domínio do e-mail não parece existir (sem registros DNS principais).", "Confirme se o endereço foi digitado corretamente."),
        RiskFlag(is_disposable, 25, "O domínio pertence a um serviço conhecido de e-mail descartável/temporário.", "Endereços descartáveis são comuns em contas falsas ou de uso único."),
        RiskFlag(domain_exists and not mx_records, 10, "O domínio existe, mas não possui registros MX configurados.", "Este domínio pode não estar apto a receber e-mails."),
        RiskFlag(domain_exists and not spf_records, 8, "Nenhum registro SPF encontrado para o domínio.", "A ausência de SPF facilita a falsificação de remetente (spoofing)."),
        RiskFlag(domain_exists and not dmarc_records, 8, "Nenhuma política DMARC encontrada para o domínio.", "A ausência de DMARC reduz a proteção contra phishing usando este domínio."),
        RiskFlag(exposure.get("status") == "exposed", 25, "O e-mail aparece em vazamentos de dados conhecidos.", "Troque a senha das contas associadas e ative autenticação de dois fatores."),
    ]

    risk = compute(flags)

    return {
        "target": email,
        "email_info": {
            "email": email,
            "domain": domain,
            "domain_exists": domain_exists,
            "is_free_webmail": is_free_webmail,
            "is_disposable": is_disposable,
            "mx_records": mx_records,
            "spf_present": bool(spf_records),
            "dmarc_present": bool(dmarc_records),
        },
        "data_exposure": exposure,
        "risk": risk,
    }
