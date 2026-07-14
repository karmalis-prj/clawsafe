# ClawSafe

**ClawHub 스킬을 스캐너 3종의 합의로 감사하고, 불일치를 라벨로 덮지 않고 그대로 공개하는 정적 리더보드.**

📊 **리더보드: https://karmalis-prj.github.io/clawsafe/**

---

## 왜

ClawHub(OpenClaw 공식 스킬 스토어)는 스킬마다 스캐너 3종을 이미 돌린다 — VirusTotal · SkillSpector(NVIDIA 정적분석) · LLM 심사. 문제는 **이 셋이 서로 자주 갈린다**는 것이다.

> arxiv [2606.01494](https://arxiv.org/abs/2606.01494): 세 스캐너가 positive로 지목한 것들의 **10.4%도 서로 겹치지 않는다.**

어느 한 스캐너만 믿으면 놓친다. 그렇다고 "다수결"로 뭉개면 갈린 지점의 정보가 사라진다.

ClawSafe는 세 번째 길을 택한다 — **만장일치 clean일 때만 SAFE로 확정(fail-closed)**하고, 스캐너가 갈린 지점은 **증거로 보존**해서 표 맨 위에 올린다.

실측 표본 26건 중 **42.3%가 스캐너 불일치(DISPUTED)**였다.

## 라벨 규칙 (fail-closed)

| 조건 | 라벨 |
|---|---|
| 3종 전부 clean | **SAFE** |
| 하나라도 malicious | **UNSAFE** (즉시) |
| 스캔 부재 · 스캐너 error · 판정 갈림 | **DISPUTED** (각 스캐너 원본 보존) |

"SAFE"는 3심 만장일치일 때만. 의심스러우면 SAFE로 안 넘어간다.

## 파이프라인

단방향. 각 단계가 파일로 커밋되어 **재현·감사 가능**하다.

```
ClawHub API  ──fetch/collect.py──▶  data/raw.jsonl
             ──judge/score.py────▶  data/verdicts.jsonl
             ──site/build.py─────▶  docs/index.html
```

```bash
python -m fetch.collect 26          # ClawHub → raw.jsonl
python judge/score.py               # raw → verdicts (합의 채점)
python site/build.py                # verdicts → 정적 리더보드
```

## 설계 원칙

- **외부 키 0개.** v0 심판은 ClawHub가 이미 돌린 스캐너 3종의 판정뿐. 외부 LLM 독립심은 v1 확장(`CLAWSAFE_JUDGES_EXTRA`로 예약).
- **경로·한도·모델명 전부 `.env`.** 코드 하드코딩 없음.
- **리더보드는 self-contained.** 인라인 CSS만, 외부 요청 0(폰트·CDN·스크립트 없음). 유일한 외부 링크는 각 스킬의 ClawHub 페이지와 arxiv 논문.
- **투명한 커버리지.** ambiguous slug(409) 등 스킵은 원인별로 집계해 숨기지 않는다.

## 데이터

- `data/raw.jsonl` — ClawHub 수집 스냅샷 (소스 + 각 스캐너 원본 판정)
- `data/verdicts.jsonl` — 합의 채점 결과 (각 행에 votes 원본 보존)

## 라이선스

MIT
