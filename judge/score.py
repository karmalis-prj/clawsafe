"""ClawHub 스캐너 3종 판정 → data/verdicts.jsonl (단방향 파이프라인 2단계).

핵심 논지 (arxiv 2606.01494 재현):
  ClawHub는 스킬마다 스캐너 3종을 이미 돌려 결과를 노출한다:
    · vt          — VirusTotal (verdict/analysis, 악성 탐지 강)
    · skillspector — NVIDIA 정적분석 (score/severity/issueCount, 가장 엄격)
    · llm          — LLM 심사 (verdict/confidence)
  이 셋은 서로 자주 갈린다(26건 표본 중 38% 불일치 실측). 어느 하나만
  믿으면 놓치는 위험이 실재한다. ClawSafe는 이 불일치를 숨기지 않고
  **만장일치만 라벨 확정(fail-closed)**하고 갈린 지점을 투명 보존한다.

라벨 규칙 (fail-closed — 안전 쪽으로만 확정):
  · 3종 전부 clean  → SAFE
  · 하나라도 malicious → UNSAFE (즉시)
  · 스캔 부재 / 스캐너 error / 판정 갈림 → DISPUTED (각 스캐너 원본 보존)
  즉 "SAFE"는 3심 만장일치일 때만. 의심스러우면 SAFE로 안 넘어간다.

v0에선 심판 = ClawHub 스캐너 3종(외부 LLM 키 0개로 완결).
외부 LLM 독립심(claude/gemini) 추가는 v1 확장 — JUDGES_EXTRA 로 예약.

경로/스캐너명은 .env 로 관리 (하드코딩 금지 원칙).
"""

from __future__ import annotations

import json
import os

# ── 설정 (전부 .env override 가능) ────────────────────────────
# v0 심판 = ClawHub 스캐너 3종. 순서는 표시용일 뿐, 판정은 순서 무관.
SCANNERS = tuple(os.environ.get("CLAWSAFE_SCANNERS", "vt,skillspector,llm").split(","))
# v1 예약: 외부 독립 LLM 심(키 있으면 활성). 지금은 비어있음 = 스캐너 3종만.
JUDGES_EXTRA = tuple(
    j for j in os.environ.get("CLAWSAFE_JUDGES_EXTRA", "").split(",") if j
)

# 판정 정규화 — 스캐너마다 status 어휘가 달라 normalizedStatus 를 1순위로.
# fail-closed: 아래 집합 밖의 값은 전부 "확정 불가"로 취급(SAFE 승격 금지).
_CLEAN = {"clean", "benign", "safe"}
_MALICIOUS = {"malicious", "unsafe"}
_SUSPICIOUS = {"suspicious", "warning"}


def _scanner_verdict(entry: dict | None) -> dict:
    """스캐너 1종의 원시 결과 → 정규화 판정 1건.

    반환: {label: 'clean'|'malicious'|'suspicious'|'unknown',
           raw: <normalizedStatus 원문>, detail: <근거 요약>}
    entry 가 없으면 label='unknown' (fail-closed: SAFE 승격 못 함).
    """
    if not entry:
        return {"label": "unknown", "raw": None, "detail": "scanner absent"}
    raw = (entry.get("normalizedStatus") or entry.get("status") or "").lower()
    if raw in _CLEAN:
        label = "clean"
    elif raw in _MALICIOUS:
        label = "malicious"
    elif raw in _SUSPICIOUS:
        label = "suspicious"
    else:
        # 'error'·미지 어휘 → unknown (스캔 실패도 안전 미확정으로 본다)
        label = "unknown"
    # 근거 요약(스캐너별 상이 필드에서 사람이 읽을 한 줄) — 투명로그 원본
    detail = (
        entry.get("recommendation")
        or entry.get("verdict")
        or entry.get("severity")
        or raw
        or "?"
    )
    return {"label": label, "raw": raw or None, "detail": str(detail)[:200]}


def ensemble(scan: dict | None) -> dict:
    """스캐너 3종 판정을 fail-closed 만장일치로 합의.

    반환:
      {label: 'SAFE'|'UNSAFE'|'DISPUTED',
       unanimous: bool,
       votes: {scanner: {label,raw,detail}},   ← 갈린 지점 투명 보존
       reason: <왜 이 라벨인가 한 줄>}

    규칙:
      · scan 자체 부재 → DISPUTED (미스캔은 SAFE 아님)
      · 어느 스캐너든 malicious → UNSAFE
      · 3종 전부 clean → SAFE
      · 그 외(suspicious/unknown/갈림) → DISPUTED
    """
    scanners = (scan or {}).get("scanners") or {}
    votes = {name: _scanner_verdict(scanners.get(name)) for name in SCANNERS}
    labels = [v["label"] for v in votes.values()]

    if not scan or not scanners:
        return {
            "label": "DISPUTED",
            "unanimous": False,
            "votes": votes,
            "reason": "no scan on record (fail-closed: not SAFE)",
        }
    if "malicious" in labels:
        hits = [n for n, v in votes.items() if v["label"] == "malicious"]
        return {
            "label": "UNSAFE",
            "unanimous": len(hits) == len(SCANNERS),
            "votes": votes,
            "reason": f"malicious flagged by: {', '.join(hits)}",
        }
    if all(lbl == "clean" for lbl in labels):
        return {
            "label": "SAFE",
            "unanimous": True,
            "votes": votes,
            "reason": "unanimous clean across all scanners",
        }
    # 갈림: suspicious 또는 unknown 섞임
    disagree = {n: v["label"] for n, v in votes.items() if v["label"] != "clean"}
    return {
        "label": "DISPUTED",
        "unanimous": False,
        "votes": votes,
        "reason": f"scanners disagree: {disagree}",
    }


def score_all(
    raw_path: str = "data/raw.jsonl", out_path: str = "data/verdicts.jsonl"
) -> dict:
    """raw.jsonl 전 스킬 채점 → verdicts.jsonl. 집계 반환.

    verdicts.jsonl 각 행:
      {slug, owner, label, unanimous, votes, reason,
       displayName, summary, source_bytes, source_truncated,
       top_status, checkedAt}
    """
    from collections import Counter

    rows = []
    with open(raw_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))

    out = []
    tally = Counter()
    for r in rows:
        scan = r.get("scan")
        e = ensemble(scan)
        meta = r.get("meta") or {}
        out.append(
            {
                "slug": r.get("slug"),
                "owner": r.get(
                    "owner"
                ),  # ambiguous slug 해소 시에만 존재 (단일 skill은 None)
                "label": e["label"],
                "unanimous": e["unanimous"],
                "votes": e["votes"],
                "reason": e["reason"],
                "displayName": meta.get("displayName"),
                "summary": meta.get("summary"),
                "source_bytes": r.get("source_bytes"),
                "source_truncated": r.get("source_truncated"),
                "top_status": (scan or {}).get("status"),
                "checkedAt": (scan or {}).get("checkedAt"),
            }
        )
        tally[e["label"]] += 1

    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        for row in out:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    return {
        "scored": len(out),
        "labels": dict(tally),
        "disputed_rate": round(tally["DISPUTED"] / len(out), 3) if out else 0.0,
        "out": out_path,
    }


if __name__ == "__main__":
    print(json.dumps(score_all(), ensure_ascii=False, indent=2))
