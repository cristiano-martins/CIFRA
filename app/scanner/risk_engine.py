"""
Motor de risco único. Recebe uma lista de "flags" (sinais já avaliados por
outros módulos) e produz score/level/reasons/recommendations. Nenhum outro
módulo deve calcular um score por conta própria — tudo passa por aqui.
"""
from dataclasses import dataclass


@dataclass
class RiskFlag:
    active: bool
    weight: int
    reason: str
    recommendation: str | None = None


def classify_level(score: int) -> str:
    if score <= 20:
        return "LOW"
    if score <= 50:
        return "MEDIUM"
    if score <= 75:
        return "HIGH"
    return "CRITICAL"


LEVEL_LABEL_PT = {"LOW": "BAIXO", "MEDIUM": "MÉDIO", "HIGH": "ALTO", "CRITICAL": "CRÍTICO"}


def compute(flags: list[RiskFlag]) -> dict:
    score = 0
    reasons: list[str] = []
    recommendations: list[str] = []

    for flag in flags:
        if flag.active:
            score += flag.weight
            reasons.append(flag.reason)
            if flag.recommendation and flag.recommendation not in recommendations:
                recommendations.append(flag.recommendation)

    score = max(0, min(100, score))
    level = classify_level(score)

    if not reasons:
        reasons.append("Nenhum indicador de risco foi identificado nas fontes consultadas.")
    if not recommendations:
        recommendations.append(
            "Nenhuma ação adicional indicada. Mesmo assim, um resultado limpo não garante segurança total."
        )

    return {
        "score": score,
        "level": level,
        "level_label": LEVEL_LABEL_PT[level],
        "reasons": reasons,
        "recommendations": recommendations,
    }
