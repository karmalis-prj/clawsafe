"""ClawHub 스킬 수집기 → data/raw.jsonl (단방향 파이프라인 1단계).

실측 확정 스펙 (2026-07-14, https://clawhub.ai):
  GET /api/v1/skills?limit=&cursor=&sort=   → {items:[...], nextCursor}
      · 목록은 slug 단위로 dedup된 대표 1개씩 (한 페이지 최대 ~200).
      · item keys = slug,displayName,summary,description,topics,tags,
                    stats,createdAt,updatedAt,latestVersion,metadata
      · latestVersion = {version,createdAt,changelog,license}  (파일목록 없음)
  GET /api/v1/skills/{slug}                 → {skill,latestVersion,metadata,owner,moderation}
      · 같은 slug이 여러 owner에 있으면 409 AMBIGUOUS_SKILL_SLUG.
        바디에 matches[]={ownerHandle,slug,ref,url}. owner-qualified 로 재조회.
  GET /api/v1/skills/{slug}/file?path=SKILL.md[&owner=X]  → raw 파일 (200KB 제한).
  GET /api/v1/skills/{slug}/scan[?owner=X]  → {skill,version,moderation,security}
      · security.scanners = {vt:{...}, ...}  ← 스캐너 불일치 투명로그의 대조 원본.

식별자는 slug. ambiguous slug(409)은 matches[].ownerHandle 로 각 owner를 개별
감사 대상으로 재수집한다 (`?owner=` 쿼리로 해결 — 실측 200).
경로/한도는 .env 로 관리 (하드코딩 금지 원칙).
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

# ── 설정 (전부 .env override 가능) ────────────────────────────
BASE = os.environ.get("CLAWHUB_BASE", "https://clawhub.ai")
API = f"{BASE}/api/v1"
FILE_MAX_BYTES = int(
    os.environ.get("CLAWHUB_FILE_MAX_BYTES", 200_000)
)  # 실측 200KB 제한
SOURCE_PATH = os.environ.get("CLAWHUB_SOURCE_PATH", "SKILL.md")
USER_AGENT = os.environ.get("CLAWHUB_UA", "clawsafe-audit/0.1 (+https://clawhub.ai)")
TIMEOUT = int(os.environ.get("CLAWHUB_TIMEOUT", 25))
_RETRY_MAX = int(os.environ.get("CLAWHUB_RETRY_MAX", 3))


def _get(path: str, params: dict | None = None) -> tuple[int, bytes, dict]:
    """단일 GET. (status, body_bytes, headers) 반환. 429는 Retry-After 존중 재시도."""
    url = f"{API}{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    for attempt in range(_RETRY_MAX):
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                return r.status, r.read(), dict(r.headers)
        except urllib.error.HTTPError as e:
            body = e.read()
            if e.code == 429 and attempt < _RETRY_MAX - 1:
                wait = int(e.headers.get("Retry-After", 2**attempt))
                time.sleep(min(wait, 30))
                continue
            return e.code, body, dict(e.headers or {})
        except (urllib.error.URLError, TimeoutError) as e:
            if attempt < _RETRY_MAX - 1:
                time.sleep(2**attempt)
                continue
            return 0, str(e).encode(), {}
    return 0, b"", {}


def fetch_skills(limit: int | None = None, sort: str = "downloads") -> list[dict]:
    """/api/v1/skills 를 nextCursor 로 순회해 스킬 메타 리스트 반환.

    limit=None 이면 전량. 목록은 이미 slug-dedup 이므로 여기선 필터 없음.
    """
    out: list[dict] = []
    cursor: str | None = None
    page_size = 200 if limit is None else min(200, limit)
    while True:
        params = {"limit": page_size, "sort": sort}
        if cursor:
            params["cursor"] = cursor
        status, body, _ = _get("/skills", params)
        if status != 200:
            raise RuntimeError(f"list skills failed: HTTP {status}: {body[:200]!r}")
        data = json.loads(body)
        out.extend(data.get("items", []))
        cursor = data.get("nextCursor")
        if limit is not None and len(out) >= limit:
            return out[:limit]
        if not cursor:
            return out


def _ambiguous_owners(body: bytes) -> list[str]:
    """409 AMBIGUOUS_SKILL_SLUG 바디에서 ownerHandle 목록 추출 (없으면 빈 리스트)."""
    try:
        matches = json.loads(body).get("matches") or []
    except json.JSONDecodeError:
        return []
    return [m["ownerHandle"] for m in matches if m.get("ownerHandle")]


def _fetch_one(slug: str, owner: str | None) -> dict:
    """단일 (slug, owner) 조합의 소스+스캔 조회. owner 지정 시 owner-qualified.

    반환: {slug, owner?, source, source_bytes, source_truncated, scan}
      scan = /scan 의 security 블록 (없으면 None) — 불일치 투명로그 원본.
    """
    fparams = {"path": SOURCE_PATH}
    sparams: dict = {}
    if owner:
        fparams["owner"] = owner
        sparams["owner"] = owner

    fstatus, fbody, _ = _get(f"/skills/{slug}/file", fparams)
    if fstatus != 200:
        return {"slug": slug, "skip": f"source_http_{fstatus}"}
    truncated = len(fbody) > FILE_MAX_BYTES
    source = fbody[:FILE_MAX_BYTES].decode("utf-8", errors="replace")

    scan = None
    sstatus, sbody, _ = _get(f"/skills/{slug}/scan", sparams)
    if sstatus == 200:
        try:
            scan = json.loads(sbody).get("security")
        except json.JSONDecodeError:
            scan = None

    rec = {
        "slug": slug,
        "source": source,
        "source_bytes": len(fbody),
        "source_truncated": truncated,
        "scan": scan,
    }
    if owner:
        rec["owner"] = owner
    return rec


def fetch_source(slug: str) -> list[dict]:
    """slug의 감사 대상(들)을 조회. 채점기 입력 레코드 리스트.

    같은 slug를 여러 owner가 가지면(409 AMBIGUOUS) 각 owner를 **개별 레코드**로
    수집한다 — owner가 다르면 다른 스킬 = 다른 감사 대상이고, slug 충돌 자체가
    감사 가치가 있는 정보다. owner-qualified 조회는 `?owner=` 파라미터로 푼다.

    반환: 성공 레코드 리스트(0개=전부 스킵). 스킵 레코드는 {slug, skip}.
    """
    fstatus, fbody, _ = _get(f"/skills/{slug}/file", {"path": SOURCE_PATH})
    if fstatus == 409:
        owners = _ambiguous_owners(fbody)
        if not owners:
            return [{"slug": slug, "skip": "ambiguous_slug_no_owner"}]
        return [_fetch_one(slug, o) for o in owners]
    if fstatus != 200:
        return [{"slug": slug, "skip": f"source_http_{fstatus}"}]
    # 단일 skill (owner 불필요) — 이미 받은 바디 재사용.
    truncated = len(fbody) > FILE_MAX_BYTES
    source = fbody[:FILE_MAX_BYTES].decode("utf-8", errors="replace")
    scan = None
    sstatus, sbody, _ = _get(f"/skills/{slug}/scan")
    if sstatus == 200:
        try:
            scan = json.loads(sbody).get("security")
        except json.JSONDecodeError:
            scan = None
    return [
        {
            "slug": slug,
            "source": source,
            "source_bytes": len(fbody),
            "source_truncated": truncated,
            "scan": scan,
        }
    ]


def write_raw(records: list[dict], path: str = "data/raw.jsonl") -> int:
    """raw.jsonl 로 기록(덮어쓰기, 재현성 위해 스냅샷 1개=1파일). 반환=행수."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    return len(records)


def collect(
    limit: int = 20, sort: str = "downloads", out: str = "data/raw.jsonl"
) -> dict:
    """엔드투엔드: 목록 → 각 slug 소스+스캔 → raw.jsonl. 집계 반환.

    스킵은 원인별로 집계(투명성 — 커버리지 구멍을 숨기지 않는다).
    """
    metas = fetch_skills(limit=limit, sort=sort)
    records = []
    skips: dict[str, int] = {}
    for m in metas:
        for src in fetch_source(m["slug"]):
            if "skip" in src:
                skips[src["skip"]] = skips.get(src["skip"], 0) + 1
                continue
            records.append({**src, "meta": m})
    n = write_raw(records, out)
    return {
        "listed": len(metas),
        "collected": n,
        "skipped": sum(skips.values()),
        "skip_reasons": skips,
        "out": out,
    }


if __name__ == "__main__":
    import sys

    lim = int(sys.argv[1]) if len(sys.argv) > 1 else 20
    print(json.dumps(collect(limit=lim), ensure_ascii=False, indent=2))
