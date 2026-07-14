"""verdicts.jsonl → docs/index.html (단방향 파이프라인 3단계, 정적 리더보드).

ClawSafe의 얼굴. 흔한 "안전 점수 랭킹"과 정반대로 **DISPUTED(스캐너 불일치)를
최상단에 올린다** — 불일치야말로 이 도구가 파는 정보이기 때문. 각 스킬 행에
vt/skillspector/llm 3종 판정을 나란히 노출 = 갈린 지점 투명 로그.

self-contained: 인라인 CSS만, 외부 요청 0 (폰트/CDN/스크립트 없음).
경로는 .env 로 관리 (하드코딩 금지 원칙).
"""

from __future__ import annotations

import html
import json
import os

VERDICTS_PATH = os.environ.get("CLAWSAFE_VERDICTS", "data/verdicts.jsonl")
OUT_PATH = os.environ.get("CLAWSAFE_SITE_OUT", "docs/index.html")
HUB_BASE = os.environ.get("CLAWHUB_BASE", "https://clawhub.ai")
PAPER = "arxiv.org/abs/2606.01494"

# 라벨 정렬: DISPUTED 먼저(핵심 가치) → UNSAFE → SAFE
_LABEL_ORDER = {"DISPUTED": 0, "UNSAFE": 1, "SAFE": 2}
# 스캐너별 판정 → 배지 클래스 (CSS 색상 매핑)
_VOTE_CLASS = {
    "clean": "v-clean",
    "malicious": "v-bad",
    "suspicious": "v-warn",
    "unknown": "v-unk",
}
_SCANNER_ORDER = ("vt", "skillspector", "llm")


def _esc(s) -> str:
    return html.escape(str(s if s is not None else ""))


def _vote_badges(votes: dict) -> str:
    cells = []
    for name in _SCANNER_ORDER:
        v = votes.get(name) or {"label": "unknown", "detail": "absent"}
        cls = _VOTE_CLASS.get(v["label"], "v-unk")
        title = _esc(v.get("detail") or v["label"])
        cells.append(
            f'<td class="vote {cls}" title="{title}">'
            f'<span class="sname">{name}</span>'
            f'<span class="slabel">{_esc(v["label"])}</span></td>'
        )
    return "".join(cells)


def _row(r: dict) -> str:
    slug = _esc(r.get("slug"))
    name = _esc(r.get("displayName") or r.get("slug"))
    summary = _esc((r.get("summary") or "")[:120])
    label = r.get("label", "DISPUTED")
    lcls = {"SAFE": "l-safe", "UNSAFE": "l-bad", "DISPUTED": "l-disp"}.get(
        label, "l-disp"
    )
    link = f"{HUB_BASE}/skills/{slug}"
    return (
        f'<tr class="{lcls}">'
        f'<td class="label"><span class="pill {lcls}">{_esc(label)}</span></td>'
        f'<td class="skill"><a href="{_esc(link)}" rel="noopener">{name}</a>'
        f'<div class="sum">{summary}</div></td>'
        f"{_vote_badges(r.get('votes') or {})}"
        f'<td class="reason">{_esc(r.get("reason"))}</td>'
        f"</tr>"
    )


def build_leaderboard(verdicts_path: str = VERDICTS_PATH, out: str = OUT_PATH) -> dict:
    """verdicts.jsonl → 정적 HTML 리더보드. 집계 반환."""
    rows = []
    with open(verdicts_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))

    counts = {"SAFE": 0, "UNSAFE": 0, "DISPUTED": 0}
    for r in rows:
        counts[r.get("label", "DISPUTED")] = counts.get(r.get("label"), 0) + 1

    rows.sort(key=lambda r: (_LABEL_ORDER.get(r.get("label"), 9), r.get("slug") or ""))
    total = len(rows) or 1
    disp_pct = round(100 * counts["DISPUTED"] / total)

    body = "\n".join(_row(r) for r in rows)
    doc = _TEMPLATE.format(
        total=len(rows),
        safe=counts["SAFE"],
        unsafe=counts["UNSAFE"],
        disputed=counts["DISPUTED"],
        disp_pct=disp_pct,
        rows=body,
        paper=PAPER,
        hub=HUB_BASE,
    )
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write(doc)
    return {"rows": len(rows), "counts": counts, "out": out}


_TEMPLATE = """<!doctype html>
<html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ClawSafe — ClawHub 스킬 스캐너 합의 감사</title>
<style>
:root{{
  --bg:#0f1216; --card:#161b22; --line:#232a33; --ink:#e6edf3; --dim:#9aa7b4;
  --accent:#e0b341; --safe:#3fb950; --bad:#f85149; --warn:#d29922; --unk:#6e7681;
}}
@media (prefers-color-scheme:light){{
  :root{{--bg:#f6f7f9;--card:#fff;--line:#e2e6ea;--ink:#1b2027;--dim:#5b6570;
    --accent:#9a6d00;--safe:#1a7f37;--bad:#cf222e;--warn:#9a6700;--unk:#8b949e;}}
}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--ink);
  font:15px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;}}
.wrap{{max-width:1040px;margin:0 auto;padding:32px 20px 80px}}
header h1{{font-size:26px;margin:0 0 6px;letter-spacing:-.01em}}
header .tag{{color:var(--accent);font-weight:600}}
header p{{color:var(--dim);margin:6px 0 0;max-width:70ch}}
a{{color:inherit}}
.stats{{display:flex;flex-wrap:wrap;gap:12px;margin:24px 0}}
.stat{{background:var(--card);border:1px solid var(--line);border-radius:10px;
  padding:14px 18px;min-width:120px}}
.stat b{{display:block;font-size:24px;font-variant-numeric:tabular-nums}}
.stat span{{color:var(--dim);font-size:12px;text-transform:uppercase;letter-spacing:.04em}}
.stat.hi b{{color:var(--accent)}}
.callout{{background:var(--card);border:1px solid var(--line);border-left:3px solid var(--accent);
  border-radius:8px;padding:12px 16px;margin:0 0 24px;color:var(--dim);font-size:13.5px}}
.callout b{{color:var(--ink)}}
.tablewrap{{overflow-x:auto;border:1px solid var(--line);border-radius:12px;background:var(--card)}}
table{{border-collapse:collapse;width:100%;min-width:760px;font-size:13.5px}}
th{{text-align:left;padding:10px 12px;color:var(--dim);font-weight:600;
  border-bottom:1px solid var(--line);font-size:11.5px;text-transform:uppercase;letter-spacing:.04em}}
td{{padding:11px 12px;border-bottom:1px solid var(--line);vertical-align:top}}
tr:last-child td{{border-bottom:0}}
.skill a{{font-weight:600;text-decoration:none}}
.skill a:hover{{text-decoration:underline}}
.sum{{color:var(--dim);font-size:12px;margin-top:2px;max-width:34ch}}
.reason{{color:var(--dim);font-size:12px;max-width:26ch}}
.pill{{display:inline-block;padding:2px 9px;border-radius:20px;font-size:11px;
  font-weight:700;letter-spacing:.03em}}
.l-safe .pill,.pill.l-safe{{background:color-mix(in srgb,var(--safe) 18%,transparent);color:var(--safe)}}
.pill.l-bad{{background:color-mix(in srgb,var(--bad) 18%,transparent);color:var(--bad)}}
.pill.l-disp{{background:color-mix(in srgb,var(--accent) 20%,transparent);color:var(--accent)}}
.vote{{text-align:center;white-space:nowrap}}
.vote .sname{{display:block;font-size:10px;color:var(--dim)}}
.vote .slabel{{display:block;font-weight:700;font-size:12px}}
.v-clean .slabel{{color:var(--safe)}}
.v-bad .slabel{{color:var(--bad)}}
.v-warn .slabel{{color:var(--warn)}}
.v-unk .slabel{{color:var(--unk)}}
tr.l-disp{{background:color-mix(in srgb,var(--accent) 5%,transparent)}}
footer{{margin-top:28px;color:var(--dim);font-size:12px}}
</style></head>
<body><div class="wrap">
<header>
<h1><span class="tag">ClawSafe</span> — 스캐너 합의 감사</h1>
<p>ClawHub 스킬을 스캐너 3종(VirusTotal · SkillSpector · LLM)의 판정으로 교차 검증한다.
<b>만장일치 clean만 SAFE로 확정(fail-closed)</b>하고, 스캐너가 갈린 지점은 숨기지 않고 그대로 노출한다.</p>
</header>

<div class="stats">
<div class="stat"><b>{total}</b><span>감사한 스킬</span></div>
<div class="stat hi"><b>{disputed}</b><span>스캐너 불일치</span></div>
<div class="stat hi"><b>{disp_pct}%</b><span>불일치율</span></div>
<div class="stat"><b>{unsafe}</b><span>UNSAFE</span></div>
<div class="stat"><b>{safe}</b><span>만장일치 SAFE</span></div>
</div>

<div class="callout">
스캐너 3종은 서로 자주 갈린다 — 이 표본의 <b>{disp_pct}%</b>가 불일치다.
어느 하나만 믿으면 놓친다(<a href="https://{paper}" rel="noopener">arxiv 2606.01494</a>: 세 스캐너 positive의 10.4%도 안 겹침).
ClawSafe는 그 불일치를 라벨로 덮지 않고 <b>증거로 보존</b>한다. 아래 표에서 갈린 판정(DISPUTED)을 맨 위에 둔다.
</div>

<div class="tablewrap"><table>
<thead><tr>
<th>합의</th><th>스킬</th><th>vt</th><th>skillspector</th><th>llm</th><th>사유</th>
</tr></thead>
<tbody>
{rows}
</tbody></table></div>

<footer>
데이터 원본: <a href="{hub}" rel="noopener">ClawHub</a> 공개 스캔 API ·
합의 규칙: malicious 1건이라도 → UNSAFE, 만장일치 clean → SAFE, 그 외 → DISPUTED(스캔 부재·스캐너 error 포함) ·
전 판정은 <code>data/verdicts.jsonl</code>로 재현 가능.
</footer>
</div></body></html>"""


if __name__ == "__main__":
    print(json.dumps(build_leaderboard(), ensure_ascii=False, indent=2))
